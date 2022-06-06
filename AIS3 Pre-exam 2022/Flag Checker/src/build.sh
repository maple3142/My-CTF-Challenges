# git clone https://github.com/splitline/Pickora
python Pickora/pickora.py -f ./test.py -o checker.pkl
hx="$(hexdump -ve '1/1 "%.2x"' checker.pkl)"
sed "s/PLACEHOLDER/$hx/" main.cpp | g++ -x c++ - -fno-stack-protector -o main
strip main
mv main flag_checker
