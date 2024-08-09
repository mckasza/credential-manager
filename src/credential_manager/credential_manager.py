import argparse
import base64
import getpass
import json
import pathlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from datetime import datetime

from rich.console import Console, Group
from rich.panel import Panel
from rich.columns import Columns

def derive_key_from_password(password, salt):
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
  )

  return kdf.derive(bytes(password, encoding='utf-8'))

def get_credential_store(file_path):
  with file_path.open('r') as f:
    credential_store = json.load(f)

  return credential_store

def get_file_path(args):
  if not args.file:
    file_path_input = input('Enter file path: ')
  else:
    file_input_path = args.file

  file_path = pathlib.WindowsPath(file_input_path)
  return file_path

def save_credential_store(file_path, credential_store):
  with file_path.open('w') as f:
    json.dump(credential_store, f, indent=2)

def verify_master_password(master_password, credential_store):
  salt = base64.b64decode(credential_store['verification']['salt'])
  key = derive_key_from_password(master_password, salt)

  encrypted_iv_plus_value = base64.b64decode(credential_store['verification']['encrypted_value'])
  iv = encrypted_iv_plus_value[:16]
  encrypted_value = encrypted_iv_plus_value[16:]

  cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  value = decryptor.update(encrypted_value)+decryptor.finalize()

  verification_hash = base64.b64decode(credential_store['verification']['hash'])

  digest = hashes.Hash(hashes.SHA256())
  digest.update(value)
  hash = digest.finalize()

  if not hash == verification_hash:
    return False
  else:
    return True

def create_handler(args, console):
  if not args.file:
    file_path_input = input('Enter file path: ')
  else:
    file_path_input = args.file

  master_password = getpass.getpass('Enter master password: ')
  master_password_2nd_entry = getpass.getpass('Re-enter master password: ')

  if not master_password == master_password_2nd_entry:
    console.print('Password entries do no match')
    return

  salt = os.urandom(16)
  derive_key_from_password(master_password, salt)
  key = derive_key_from_password(master_password, salt)

  verification_value = os.urandom(32)

  iv = os.urandom(16)
  cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  encrypted_value = iv + encryptor.update(verification_value) + encryptor.finalize()

  digest = hashes.Hash(hashes.SHA256())
  digest.update(verification_value)
  verification_hash = digest.finalize()

  credential_store = {
    'verification': {
      'encrypted_value': base64.b64encode(encrypted_value).decode('utf-8'), 
      'salt': base64.b64encode(salt).decode('utf-8'),
      'hash': base64.b64encode(verification_hash).decode('utf-8')
    },
    'credentials': []
  }

  file_path = pathlib.WindowsPath(file_path_input)

  with file_path.open('w') as f:
    json.dump(credential_store, f, indent=2)

def list_handler(args, console):
  file_path = get_file_path(args)
  credential_store = get_credential_store(file_path)

  for i, cred in enumerate(credential_store['credentials']):
    console.print(
      Columns(
        [
          f'{i+1}:',
          Panel(
            f'Username: [blue on grey70] {cred["username"]} [/]\nAdded on: [blue on grey70] {cred["added_on"]} [/]', 
            title=f'[purple]{cred["name"]}[/]', 
            expand=False
          )
        ],
        title='Credentials'
      )
    )

def add_handler(args, console):
  file_path = get_file_path(args)
  credential_store = get_credential_store(file_path)

  name = input('Enter a name for this credential: ')

  username = input('Enter username: ')
  password = getpass.getpass('Enter password: ')
  password_2nd_entry = getpass.getpass('Re-enter password: ')

  if not password == password_2nd_entry:
    console.print('Password entries do not match')
    return
  
  password_2nd_entry = None

  master_password = getpass.getpass('Enter master password: ')
  if not verify_master_password(master_password, credential_store):
    console.print('Invalid master password')
    return

  salt = base64.b64decode(credential_store['verification']['salt'])
  key = derive_key_from_password(master_password, salt)

  iv = os.urandom(16)
  cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  encrypted_password = iv + encryptor.update(bytes(password, encoding='utf-8')) + encryptor.finalize()

  new_credential = {
    'name': name,
    'username': username,
    'encrypted_password': base64.b64encode(encrypted_password).decode('utf-8'),
    'added_on': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
  }

  credential_store['credentials'].append(new_credential)

  save_credential_store(file_path, credential_store)
  console.print(f'Credential \'{name}\' was stored successfully')

def delete_handler(args, console):
  file_path = get_file_path(args)
  credential_store = get_credential_store(file_path)

  if len(credential_store['credentials']) == 0:
    print('There are no credentials to delete')

  index = args.index-1

  try:
    if index < 0:
      raise IndexError
    credential_to_delete = credential_store['credentials'][index]
  except IndexError:
    error_console = Console(stderr=True)
    if len(credential_store['credentials']) == 1:
      error_console.print('Error: Index must be 1 since the credential store only contains a single credential')
    else:
      error_console.print(f'Error: Index must be between 1 and {len(credential_store["credentials"])}')
    return

  confirmation_message = f'Confirm deletion of credential \'{credential_to_delete["name"]}\' at index {index+1} [Y/n]: '
  confirm_input = console.input(confirmation_message)
  valid_input = False
  deletion_confirmed = False
  while not valid_input:
    if confirm_input == 'Y':
      valid_input = True
      deletion_confirmed = True
    elif confirm_input == 'n':
      valid_input = True
    else:
      console.print(f'Invalid input \'{confirm_input}\'')
      confirm_input = console.input(confirmation_message)

  if deletion_confirmed:
    credential_store['credentials'].remove(credential_to_delete)
    save_credential_store(file_path, credential_store)
    console.print('Credential was deleted successfully')
  else:
    console.print('Exiting without performing credential deletion')

def show_password_handler(args, console):
  file_path = get_file_path(args)
  credential_store = get_credential_store(file_path)

  index = args.index-1
  credential = credential_store['credentials'][index]

  master_password = getpass.getpass('Enter master password: ')
  if not verify_master_password(master_password, credential_store):
    console.print('Invalid master password')
    return

  salt = base64.b64decode(credential_store['verification']['salt'])
  key = derive_key_from_password(master_password, salt)

  encrypted_iv_plus_password = base64.b64decode(credential['encrypted_password'])
  iv = encrypted_iv_plus_password[:16]
  encrypted_password = encrypted_iv_plus_password[16:]

  cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  plaintext_password = decryptor.update(encrypted_password)+decryptor.finalize()

  console.print(plaintext_password.decode('utf-8'))

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('file')

  subparsers = parser.add_subparsers()

  create_parser = subparsers.add_parser('create')
  create_parser.set_defaults(func=create_handler)

  add_parser = subparsers.add_parser('add')
  add_parser.set_defaults(func=add_handler)

  list_parser = subparsers.add_parser('list')
  list_parser.set_defaults(func=list_handler)

  delete_parser = subparsers.add_parser('delete')
  delete_parser.add_argument('-i', '--index', required=True, type=int)
  delete_parser.set_defaults(func=delete_handler)

  show_password_parser = subparsers.add_parser('show_password')
  show_password_parser.add_argument('-i', '--index', required=True, type=int)
  show_password_parser.set_defaults(func=show_password_handler)

  args = parser.parse_args()

  console = Console()

  args.func(args, console)

if __name__ == '__main__':
  main()
