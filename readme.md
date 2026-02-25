python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4

python3 controller.py -f shadow.txt -u alice -p 5000 -b 2 -k 50000 -l 3 --min-workers 1
