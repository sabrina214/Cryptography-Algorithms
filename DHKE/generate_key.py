import json, os, sys


if __name__ == '__main__':
  name = input('Enter your name: ')
  if not os.path.exists(f'./secret_{name}.txt'):
    print('[ERR] Secret file not found. Creating one...')
    os.system(f'python publish.py {name}')
  
  peer = input("Enter peer's name: ")

  with open('partial_keys.json', 'r') as partial_keys_file, \
      open(f'secret_{name}.txt', 'r') as my_secret_file, \
      open('dhke_parameters.json', 'r') as dhke_parameters_file:

    partial_keys = json.load(partial_keys_file)
    secret = my_secret_file.read()
    dhke_parameters = json.load(dhke_parameters_file)

    secret = int(secret)
    try:
      secret_key = pow(partial_keys[peer], secret, dhke_parameters['p'])
    except KeyError:
      print(f'[ERR] {peer} has not yet published his partial key. Try again later')
      sys.exit()
    print(f'[INFO] Applying your secret to partial secret of {peer}')
    print('[INFO] Secret key is:', secret_key)
