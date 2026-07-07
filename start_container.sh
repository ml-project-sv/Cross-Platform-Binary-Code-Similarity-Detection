docker build -t bincomp .
docker run -it --rm -v "$(pwd):/work" -w /work bincomp bash