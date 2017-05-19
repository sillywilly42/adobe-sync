#!/usr/bin/python

"""Module for syncing Adobe AD groups with the Adobe Management Portal.

Usage: adobe_sync.py [--dummy] [--debug]
  --dummy: Sets the testOnly flag when talking to the API, commands will not really be executed.
  --debug: Very verbose output!
"""

import json
import logging
import sys
import time
from urllib import urlencode

import jwt  # pip install --upgrade PyJWT
# On macOS:
# pip install --upgrade python-ldap --global-option=build_ext \
#                                   --global-option="-I$(xcrun --show-sdk-path)/usr/include/sasl"
import ldap
import requests  # pip install --upgrade requests

# Map of Adobe product configuarion names (from the portal), to AD group
SOFTWARE_GROUPS = {
   'Adobe Captivate': 'CN=Captivate,OU=Software Groups,DC=megacorp,DC=com',
   'Adobe Illustrator': 'CN=Illustrator,OU=Software Groups,DC=megacorp,DC=com',
}

# These users should never be removed from the portal (ie. admin users).
# They should be manually managed via the portal.
UNREMOVABLE_USERS = ['admin@megacorp.com']


class ActiveDirectory(object):
  """Gathers together methods for querying AD using LDAP."""

  LDAP_SERVER = 'ldaps://ldap.megacorp.com:636'
  USER_BASE_DN = 'OU=Users,DC=megacorp,DC=com'
  BIND_ACCOUNT = 'CN=adobe-sync,OU=Robots,DC=megacorp,DC=com'
  BIND_PASSWORD = 'hunter2'
  MAIL_ATTR = 'email'
  FIRSTNAME_ATTR = 'firstname'
  LASTNAME_ATTR = 'lastname'

  def __init__(self):
    self.connection = ldap.initialize(self.LDAP_SERVER)
    self.connection.bind_s(self.BIND_ACCOUNT, self.BIND_PASSWORD)
    self.dn_to_email_cache = {}
    self.email_to_user_details = {}

  def __del__(self):
    self.connection.unbind_s()

  def query_ldap_for_group(self, group_dn, counter=0):
    """Returns list of users (DNs) belonging to the specified group."""
    search_filter = '(&(objectClass=group)(distinguishedName=%s))' % group_dn
    attribute = 'member;range=%s-%s' % (counter, counter + 1499)
    base_dn = 'OU=%s' % group_dn.split('OU=', 1)[1]
    ldap_result_id = self.connection.search(base_dn, ldap.SCOPE_SUBTREE, search_filter, [attribute])

    result_set = []
    while True:
      result_type, result_data = self.connection.result(ldap_result_id, 0)
      if not result_data:
        for result in list(result_set):
          if 'Security Groups' in result:
            logging.debug('Group contains sub-group: %s', result)
            result_set.extend(self.query_ldap_for_group(result))
        return list(set(result_set))
      else:
        if result_type == ldap.RES_SEARCH_ENTRY or result_type == ldap.RES_SEARCH_RESULT:
          if result_data[0][1]:
            key, value = result_data[0][1].popitem()
            result_set.extend(value)
            if not key.endswith('*'):
              logging.debug('Group is large, getting results (%s-%s): %s',
                            counter + 1500, counter + 1500 + 1499, group_dn)
              result_set.extend(self.query_ldap_for_group(group_dn, counter=counter + 1500))

  def process_group_members(self, member_dns):
    """Process the user DNs

    DNs are useless to us, we need to get at the AD "mail" property. So we have
    to query LDAP for every user. Sometimes a user will be in multiple groups
    and we don't want to end up querying again so we cache the lookups in a
    dictionary (dn_to_email_cache).

    Returns a list of emails (AD mail property).
    """
    emails = []
    for member in member_dns:
      if self.dn_to_email_cache.get(member):
        emails.append(self.dn_to_email_cache[member])
      else:
        search_filter = ('(distinguishedName=%s)' %
                         member.replace('(', r'\(').replace(')', r'\)'))
        result = self.connection.search_s(self.USER_BASE_DN, ldap.SCOPE_SUBTREE,
                                          search_filter,
                                          [self.MAIL_ATTR, self.FIRSTNAME_ATTR, self.LASTNAME_ATTR])
        if result:
          email = result[0][1][self.MAIL_ATTR][0].strip().lower()
          self.dn_to_email_cache[member] = email
          self.email_to_user_details[email] = {
              'firstname': result[0][1][self.FIRSTNAME_ATTR][0].strip(),
              'lastname': result[0][1][self.LASTNAME_ATTR][0].strip()
          }
          emails.append(email)
    return sorted(list(set(emails)))


class AdobeSync(object):
  """Object collects methods for interacting with the Adobe Portal."""

  PRIVATE_KEY_PATH = 'adobe-private.key'

  def __init__(self):
    with open(self.PRIVATE_KEY_PATH, 'r') as priv_key_file:
      priv_key = priv_key_file.read()

    self.config = {
        'host': 'usermanagement.adobe.io',
        'endpoint': 'v2/usermanagement',
        'ims_host': 'ims-na1.adobelogin.com',
        'ims_endpoint_jwt': '/ims/exchange/jwt',
        'org_id': 'my_org_id@AdobeOrg',
        'api_key': 'my_api_key',
        'client_secret': 'my_client_secret',
        'tech_acct': 'my_tech_account@techacct.adobe.com',
        'priv_key': priv_key,
    }

    self.jwt_token = self._generate_jwt()
    logging.debug('JSON Web Token:\n%s', self.jwt_token)

    self.access_token = self._obtain_access_token()
    self.portal_users = {}
    self.user_mods_additions = {}
    self.user_mods_subtractions = {}
    self.commands = []

  def _generate_jwt(self):
    # set expiry time for JSON Web Token
    expiry_time = int(time.time()) + 60 * 60 * 24

    # create payload
    payload = {
        'exp' : expiry_time,
        'iss' : self.config['org_id'],
        'sub' : self.config['tech_acct'],
        'aud' : 'https://%s/c/%s' % (self.config['ims_host'], self.config['api_key']),
        'https://%s/s/ent_user_sdk' % self.config['ims_host']: True,
    }

    return jwt.encode(payload, self.config['priv_key'], algorithm='RS256').decode('utf-8')

  def _obtain_access_token(self):
    # method parameters
    url = 'https://%s%s' % (self.config['ims_host'], self.config['ims_endpoint_jwt'])
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cache-Control': 'no-cache',
    }

    body_credentials = {
        'client_id' : self.config['api_key'],
        'client_secret' : self.config['client_secret'],
        'jwt_token' : self.jwt_token,
    }
    body = urlencode(body_credentials)

    # send http request
    res = requests.post(url, headers=headers, data=body)
    # evaluate response
    if res.status_code == 200:
      # extract token
      access_token = json.loads(res.text)['access_token']

      logging.debug('Your access token is:\n%s', access_token)
      return access_token
    else:
      logging.critical('ERROR: Could not obtain access token :(\n%d\n%s\n%s',
                       res.status_code, res.headers, res.text)
      sys.exit(1)

  def _send_portal_request(self, request_type='get', command='users', page=0, data=None,
                           dummy=False):
    # method parameters
    url = 'https://%s/%s/%s/%s' % (self.config['host'], self.config['endpoint'], command,
                                   self.config['org_id'])
    if page is not None:
      url += '/%d' % page

    if dummy:
      url += '?testOnly=true'

    headers = {
        'Content-type' : 'application/json',
        'Accept' : 'application/json',
        'x-api-key' : self.config['api_key'],
        'Authorization' : 'Bearer %s' % self.access_token,
    }

    # prepare body
    if data:
      body = json.dumps(data)
      logging.debug('Size of body in KB: %f', sys.getsizeof(body) / 1024.0)

    # send http request
    if request_type == 'post':
      res = requests.post(url, headers=headers, data=body)
    elif request_type == 'get':
      res = requests.get(url, headers=headers)
    else:
      logging.critical('ERROR: Unknown request type, should be GET or POST.')
      sys.exit(1)

    logging.debug('HTTP status code: %d', res.status_code)
    logging.debug('HTTP response headers:\n%s', res.headers)

    if res.status_code != 200:
      logging.critical('The server rejected this request. Perhaps it\'s busy.')
      sys.exit(1)
    return res.text

  def get_all_portal_users(self):
    """Get all the users from the portal and convert into a useful format.

    Sets self.portal_users = {user emails: [list of groups]}
    """
    completed = False
    page = 0
    users = []

    # The portal returns up to 200 users per "page", the last page returns an
    # attribute lastPage = True.
    while not completed:
      response = json.loads(self._send_portal_request(page=page))

      if response.get('result') != 'success':
        logging.critical('ERROR: Response from Adobe portal was bad: %s', response)
        sys.exit(1)

      completed = response.get('lastPage')
      users.extend(response.get('users', []))

    self.portal_users = {x['email'].lower(): x.get('groups', []) for x in users}

    logging.debug('Portal users:\n%s', self.portal_users)

  def compare_group_memberships(self, ad_groups):
    """Compares the provided AD group mappings with the Adobe portal mappings.

    Args:
      ad_groups: a dict of {'Adobe portal config name': [list of emails]}
    """

    # Transform ad_groups into a dict of {email: [list of groups]}
    ad_members_to_groups = {}
    for group, members in ad_groups.items():
      for member in members:
        groups = ad_members_to_groups.get(member, [])
        groups.append(group)
        ad_members_to_groups[member] = groups

    # Process AD groups for users who need adding to portal, or existing users
    # who need additional products added to their profiles.
    for group, members in ad_groups.items():
      for member in members:
        if group not in self.portal_users.get(member, []):
          additions = self.user_mods_additions.get(member, [])
          additions.append(group)
          self.user_mods_additions[member] = additions

    # Process AD groups for users who need to be removed from the portal, or
    # who need to have one or more products removed from their profile.
    for user, groups in self.portal_users.iteritems():
      ad_groups = ad_members_to_groups.get(user)
      if ad_groups:
        groups_for_removal = set(groups) - set(ad_groups)
        if groups_for_removal:
          self.user_mods_subtractions[user] = list(groups_for_removal)
      else:
        # If the user isn't in any AD groups then they should be removed from
        # all portal groups.
        self.user_mods_subtractions[user] = groups

    logging.debug('user_mods_additions: %s', self.user_mods_additions)
    logging.debug('user_mods_subtractions: %s', self.user_mods_subtractions)

  def generate_portal_commands(self, email_to_user_details):
    """Prepare the additions, deletions and removals."""
    commands = []
    # Process the additions first
    for user, groups in self.user_mods_additions.iteritems():
      commands.append(
          {'user': user,
           'do': [{'createFederatedID': {'country': 'US',
                                         'email': user,
                                         'firstname': email_to_user_details[user]['firstname'],
                                         'lastname': email_to_user_details[user]['lastname'],
                                         'option': 'ignoreIfAlreadyExists'}},
                  {'add': {'product': groups}}]}
      )

    # Process the removals
    for user, groups in self.user_mods_subtractions.iteritems():
      if user in self.user_mods_additions.keys():
        # User already has an addition command so we'll add onto that.
        for command_dict in commands:
          if command_dict['user'] == user:
            command_dict['do'].append(
                {'remove': {'product': groups}}
            )
            break
      else:
        if set(self.portal_users[user]) == set(groups) and user not in UNREMOVABLE_USERS:
          # All the user's groups are being removed, we should remove the user.
          commands.append(
              {'user': user,
               'do': [{'removeFromOrg': {}}]}
          )
        else:
          # Just some of the user's groups are being removed.
          if groups:
            commands.append(
                {'user': user,
                 'do': [{'remove': {'product': groups}}]}
            )

    self.commands = commands

  def preprocess_commands(self):
    """Preprocess list of commands to comply with API limitations.

    There's a limit of 10 commands per request, 10 actions per command, and 10 products per
    add / remove operation. We therefore need to re-process the commands into smaller chunks.

    We haven't structured our commands in a way where there could be more than 10 actions per
    command, so we really only need to care about more than 10 products per user.

    Returns a list of lists of commands, no more than 10 per inner list:
    [[command1, command2, ...], [command11, command 12, ...]]
    """
    expanded_commands = []

    for command in self.commands:  # Look through each command...
      operation_added = False
      for operation in command['do']:  # Look through each action...
        # Check if this action is an add operation, and if it's adding more than 10 products.
        if operation.get('add') and len(operation['add']['product']) > 10:
          # We need to split the groups into batches of 10 and create a new command for each batch.
          for groups in [operation['add']['product'][i:i + 10]
                         for i in xrange(0, len(operation['add']['product']), 10)]:
            # Create a copy of the current command.
            new_command = dict(command)
            new_do_operations = []
            for old_operation in command['do']:  # Work through all the operations in the command
              if old_operation.get('add'):  # We want to replace add operations but leave others
                new_do_operations.append({'add': {'product': groups}})
              elif old_operation.get('remove'):  # Except remove operations which we'll handle below
                continue
              else:
                new_do_operations.append(old_operation)
            new_command['do'] = new_do_operations
            expanded_commands.append(new_command)
            operation_added = True  # Set a flag to show something changed.

        # Same again, but this time with remove operations.
        elif operation.get('remove') and len(operation['remove']['product']) > 10:
          for groups in [operation['remove']['product'][i:i + 10]
                         for i in xrange(0, len(operation['remove']['product']), 10)]:
            new_command = dict(command)
            new_do_operations = []
            for old_operation in command['do']:
              if old_operation.get('remove'):
                new_do_operations.append({'remove': {'product': groups}})
              elif old_operation.get('add'):
                continue
              else:
                new_do_operations.append(old_operation)
            new_command['do'] = new_do_operations
            expanded_commands.append(new_command)
            operation_added = True

      # This is an unusual constuct for...else - the else block gets executed once the for loop has
      # completed.
      else:
        if not operation_added:
          # Add the command if it didn't contain a add or remove block with more than 10 groups.
          expanded_commands.append(command)

    # Return the expanded_commands list chunked into lists of 10 commands.
    return [expanded_commands[i:i + 10] for i in xrange(0, len(expanded_commands), 10)]

  def run_commands(self, command_chunks, dummy=False):
    """Push a list of lists of commands to the portal."""

    for command in command_chunks:
      response_body = self._send_portal_request(request_type='post', command='action', page=None,
                                                data=command, dummy=dummy)
      response = json.loads(response_body)
      if response['result'] == 'success':
        logging.info('Request completed successfully.')
      else:
        logging.critical('Server response: %d completed, %d failed.',
                         response['completed'], response['notCompleted'])
        for error in response['errors']:
          logging.critical('User: %s Error: %s (%s)',
                           error['user'], error['message'], error['errorCode'])


def main(argv):
  """Main method for module."""

  dummy = '--dummy' in argv
  if '--debug' in argv:
    logging.basicConfig(level=logging.DEBUG)

  active_directory = ActiveDirectory()
  ad_group_memberships = {}
  for name, distinguished_name in SOFTWARE_GROUPS.items():
    logging.debug('Processing %s...', name)
    member_dns = active_directory.query_ldap_for_group(distinguished_name)
    emails = active_directory.process_group_members(member_dns)
    ad_group_memberships[name] = emails

  logging.debug('ad_group_memberships:\n%s', ad_group_memberships)
  logging.debug('email_to_user_details:\n%s', active_directory.email_to_user_details)

  adobe_sync = AdobeSync()
  adobe_sync.get_all_portal_users()
  adobe_sync.compare_group_memberships(ad_group_memberships)
  adobe_sync.generate_portal_commands(active_directory.email_to_user_details)
  chunked_commands = adobe_sync.preprocess_commands()
  adobe_sync.run_commands(chunked_commands, dummy)


if __name__ == '__main__':
  main(sys.argv)
