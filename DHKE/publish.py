import random, json, os, sys


if __name__ == '__main__':
  if len(sys.argv) == 2:
    name = sys.argv[1]
  else:
    name = input('Enter your name(public): ')

  with open('dhke_parameters.json', 'r') as dhke_parameters_file, \
      open(f'secret_{name}.txt', 'w') as secret_file:
    
    dhke_parameters = json.load(dhke_parameters_file)
    p = dhke_parameters['p']
    q = dhke_parameters['q']
    g = dhke_parameters['g']
 
    # generate a random secret
    x = random.randint(1, q - 1)
    secret_file.write(str(x))
    print(f'[INFO] Secret saved in ./secret_{name}.txt')

    # compute and publish partial keys
    if os.path.exists('partial_keys.json'):
      partial_keys_json = open('partial_keys.json', 'r')
      partial_keys = json.load(partial_keys_json)
      partial_keys.update({f'{name}': pow(g, x, p)})

      fp = open('partial_keys_tmp.json', 'w')
      json.dump(partial_keys, fp, indent=2)
      os.system('mv partial_keys_tmp.json partial_keys.json')
      fp.close()

    else:
      partial_keys_json = open('partial_keys.json', 'w')
      partial_keys = {f'{name}': pow(g, x, p)}
      json.dump(partial_keys, partial_keys_json, indent=2)

    partial_keys_json.close()
    print('[INFO] Partial key saved in ./partial_keys.json')