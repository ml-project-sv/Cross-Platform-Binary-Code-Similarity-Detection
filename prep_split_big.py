import sys, json, glob, numpy as np
sys.path.insert(0, '/home/claude/gemini-pytorch')
from utils import get_f_dict, read_graph, partition_data, generate_epoch_pair
DATA='/home/claude/data_angr_big/acfgSSL_angr_7/'
BATCH=5; np.random.seed(0)
f_names=sorted(glob.glob(DATA+'*.json'))           # glob actual files
print(f"{len(f_names)} ACFG files")
fdict=get_f_dict(f_names)
graphs,classes=read_graph(f_names,fdict,7)
print(f"{len(graphs)} graphs / {len(classes)} functions")
perm=np.random.permutation(len(classes))
np.save('/home/claude/data_angr_big/class_perm.npy', perm)
G=partition_data(graphs,classes,[0.8,0.1,0.1],perm)
Gs_tr,c_tr,Gs_dev,c_dev,Gs_te,c_te=G
print(f"train {len(Gs_tr)} / dev {len(Gs_dev)} / test {len(Gs_te)} graphs")
_,vid=generate_epoch_pair(Gs_dev,c_dev,BATCH,output_id=True)
_,tid=generate_epoch_pair(Gs_te,c_te,BATCH,output_id=True)
json.dump(vid,open('/home/claude/data_angr_big/valid.json','w'))
json.dump(tid,open('/home/claude/data_angr_big/test.json','w'))
print(f"valid {len(vid)} batches | test {len(tid)} batches")
