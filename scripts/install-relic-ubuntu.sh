sudo apt-get install libgmp3-dev

wget https://github.com/relic-toolkit/relic/archive/relic-toolkit-0.4.0.tar.gz
tar -xvzf relic-toolkit-0.4.0.tar.gz
cd relic-toolkit-0.4.0.tar.gz
./preset/gmp-pbc-128.sh
cmake .
make
sudo make install
