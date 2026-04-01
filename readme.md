python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4
python3 worker.py -c <controller_ip> -p 5000 -t 4

python3 controller.py -f shadow.txt -u alice -p 5000 -b 2 -k 50000 -l 3 --min-workers 1


python3 controller.py -f shadow.txt -u user1 -p 8080 -b 2 -c 10000 -k 500 -l 3

python3 worker.py -c 127.0.0.1 -p 5000 -t 4 --checkpoint-file worker1_ckpt.json