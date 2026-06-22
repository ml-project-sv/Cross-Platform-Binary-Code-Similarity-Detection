"""
train.py
========
Task-independent PRE-TRAINING of Gemini -- this is the "first train" from the
paper (Section 3.5 / 4.5). It trains the Siamese Structure2vec model on
Dataset I (OpenSSL ACFGs) so that embeddings of functions compiled from the
same source end up close together.

The script is instrumented for TIMING: it prints the wall-clock time of every
epoch and, after the first epoch, projects how long the full run will take.

Usage
-----
  # quick timing probe: time the first 200 optimizer steps, then stop
  python train.py --time_probe 200

  # short real run (paper says ~5 epochs already gives decent AUC)
  python train.py --epochs 5

  # full pre-training (paper default; best AUC)
  python train.py --epochs 100

  python train.py -h    # all options
"""

import argparse
import os
import time
import json
from datetime import datetime, timedelta

import numpy as np

from model import GraphNN
from utils import (get_f_name, get_f_dict, read_graph, partition_data,
                   generate_epoch_pair, train_epoch, get_auc_epoch)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--data_dir', type=str, default='/home/claude/data_angr_big/acfgSSL_angr_7/')
    p.add_argument('--device', type=str, default=None,
                   help="'cpu', 'cuda', or auto-detect if omitted")
    p.add_argument('--fea_dim', type=int, default=7, help='node feature dim')
    p.add_argument('--embed_dim', type=int, default=64, help='embedding size p')
    p.add_argument('--embed_depth', type=int, default=2, help='depth of sigma()')
    p.add_argument('--output_dim', type=int, default=64)
    p.add_argument('--iter_level', type=int, default=5, help='message-pass iters T')
    p.add_argument('--lr', type=float, default=1e-4)
    p.add_argument('--epochs', type=int, default=100)
    p.add_argument('--batch_size', type=int, default=5, help='anchor graphs/batch')
    p.add_argument('--seed', type=int, default=0)
    p.add_argument('--save_path', type=str, default='./saved_model/gemini')
    p.add_argument('--test_freq', type=int, default=1,
                   help='evaluate validation AUC every N epochs (0 = never)')
    p.add_argument('--time_probe', type=int, default=0,
                   help='if >0: run only this many optimizer steps and report '
                        'per-step time, then exit (no full epoch)')
    p.add_argument('--limit_train_batches', type=int, default=None,
                   help='cap optimizer steps per epoch (for quick test runs); '
                        'omit for a full faithful epoch over all training data')
    return p.parse_args()


def main():
    args = parse_args()
    np.random.seed(args.seed)

    if args.device is None:
        import torch
        args.device = 'cuda' if torch.cuda.is_available() else 'cpu'

    print("=" * 60)
    for k, v in vars(args).items():
        print(f"  {k:12s}: {v}")
    print("=" * 60)

    # ---- which files make up Dataset I ----
    SOFTWARE = ('openssl-1.0.1f-', 'openssl-1.0.1u-')
    ARCHS = ('armeb-linux', 'i586-linux', 'mips-linux')
    OPTS = ('-O0', '-O1', '-O2', '-O3')
    VERSIONS = ('v54',)

    t0 = time.time()
    import glob
    f_names = sorted(glob.glob(args.data_dir + '*.json'))
    func_dict = get_f_dict(f_names)
    graphs, classes = read_graph(f_names, func_dict, args.fea_dim)
    print(f"Loaded {len(graphs)} graphs / {len(classes)} functions "
          f"in {time.time()-t0:.1f}s")

    # ---- reproduce the paper's train/dev/test split via class_perm.npy ----
    perm_path = os.path.join(os.path.dirname(args.data_dir.rstrip('/')),
                             'class_perm.npy')
    if os.path.isfile(perm_path):
        perm = np.load(perm_path)
        if len(perm) < len(classes):
            perm = np.random.permutation(len(classes))
    else:
        perm = np.random.permutation(len(classes))

    (Gs_train, cls_train, Gs_dev, cls_dev,
     Gs_test, cls_test) = partition_data(graphs, classes, [0.8, 0.1, 0.1], perm)
    print(f"Train: {len(Gs_train)} graphs / {len(cls_train)} funcs | "
          f"Dev: {len(Gs_dev)} / {len(cls_dev)} | "
          f"Test: {len(Gs_test)} / {len(cls_test)}")

    # ---- fixed validation pairs (reuse repo's data/valid.json if present) ----
    valid_json = os.path.join(os.path.dirname(args.data_dir.rstrip('/')),
                              'valid.json')
    valid_ids = None
    if os.path.isfile(valid_json):
        with open(valid_json) as f:
            valid_ids = json.load(f)
        print(f"Loaded fixed validation pairs from {valid_json} "
              f"({len(valid_ids)} batches)")

    # ---- model ----
    model = GraphNN(n_x=args.fea_dim, n_embed=args.embed_dim,
                    depth_embed=args.embed_depth, n_o=args.output_dim,
                    iter_level=args.iter_level, lr=args.lr, device=args.device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model on {args.device} | {n_params} trainable parameters")

    # =====================================================================
    # TIMING PROBE: just measure per-step time on a partial epoch, then exit
    # =====================================================================
    if args.time_probe > 0:
        print(f"\n[time probe] timing {args.time_probe} optimizer steps ...")
        t = time.time()
        loss = train_epoch(model, Gs_train, cls_train, args.batch_size,
                           limit_batches=args.time_probe)
        dt = time.time() - t
        steps = args.time_probe
        per_step = dt / steps
        steps_per_epoch = (len(Gs_train) + args.batch_size - 1) // args.batch_size
        est_epoch = per_step * steps_per_epoch
        print(f"[time probe] {steps} steps in {dt:.1f}s "
              f"({per_step*1000:.1f} ms/step), mean loss {loss:.4f}")
        print(f"[time probe] ~{steps_per_epoch} steps / epoch  =>  "
              f"~{est_epoch:.1f}s/epoch ({est_epoch/60:.1f} min)")
        for E in (5, 100):
            print(f"[time probe] projected {E:3d} epochs: "
                  f"~{est_epoch*E/60:.1f} min ({est_epoch*E/3600:.2f} h)")
        return

    # =====================================================================
    # FULL TRAINING LOOP (the "first train")
    # =====================================================================
    os.makedirs(os.path.dirname(args.save_path), exist_ok=True)
    best_auc = 0.0
    epoch_times = []

    if args.test_freq:
        auc0, *_ = get_auc_epoch(model, Gs_dev, cls_dev, args.batch_size,
                                 load_id=valid_ids)
        print(f"Initial validation AUC = {auc0:.4f}")

    train_start = time.time()
    for ep in range(1, args.epochs + 1):
        t = time.time()
        loss = train_epoch(model, Gs_train, cls_train, args.batch_size,
                           limit_batches=args.limit_train_batches)
        dt = time.time() - t
        epoch_times.append(dt)

        msg = f"EPOCH {ep:3d}/{args.epochs}  loss={loss:.4f}  {dt:.1f}s"
        if args.test_freq and ep % args.test_freq == 0:
            auc, *_ = get_auc_epoch(model, Gs_dev, cls_dev, args.batch_size,
                                    load_id=valid_ids)
            msg += f"  val_AUC={auc:.4f}"
            if auc > best_auc:
                best_auc = auc
                model.save(args.save_path + '_best.pt')
                msg += "  [saved best]"
        print(msg)

        # after epoch 1, project the remaining time
        if ep == 1 and args.epochs > 1:
            eta = epoch_times[0] * (args.epochs - 1)
            done = datetime.now() + timedelta(seconds=eta)
            print(f"  -> ~{epoch_times[0]:.1f}s/epoch; est. total "
                  f"{epoch_times[0]*args.epochs/60:.1f} min, "
                  f"finish ~{done:%H:%M:%S}")

    total = time.time() - train_start
    print("=" * 60)
    print(f"Done. {args.epochs} epochs in {total/60:.1f} min "
          f"(mean {np.mean(epoch_times):.1f}s/epoch). Best val AUC = {best_auc:.4f}")
    try:
        model.load(args.save_path + "_best.pt")
        ta,*_ = get_auc_epoch(model, Gs_test, cls_test, args.batch_size)
        print(f"TEST AUC (held-out, best model) = {ta:.4f}")
    except Exception as e:
        print("test eval skipped:", e)


if __name__ == '__main__':
    main()
