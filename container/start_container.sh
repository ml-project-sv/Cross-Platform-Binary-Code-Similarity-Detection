docker build -t bincomp .
docker run -it --rm -v "$1:/work" -w /work bincomp bash