sudo apt-get update
sudo apt-get install -y libgmp3-dev cmake

git clone https://github.com/relic-toolkit/relic
cd relic
./preset/gmp-pbc-128.sh
export RELIC_LOC=$(readlink -f .)
cmake . && make && sudo make install
