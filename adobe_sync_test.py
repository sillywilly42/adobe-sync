#!/usr/bin/python

"""Tests for adobe_sync module."""

import unittest

import adobe_sync


class AdobeSyncUnderTest(adobe_sync.AdobeSync):
  """Subclasses AdobeSync in order to override init method."""

  def __init__(self):

    self.config = {
        'host': 'non-existent.adobe.io',
        'endpoint': 'v2/usermanagement',
        'ims_host': 'non-existent.adobelogin.com',
        'ims_endpoint_jwt': '/ims/exchange/jwt',
        'org_id': '12345@AdobeOrg',
        'api_key': '12345',
        'client_secret': '12345',
        'tech_acct': '12345@techacct.adobe.com',
        'priv_key': '12345',
    }

    self.portal_users = {}
    self.user_mods_additions = {}
    self.user_mods_subtractions = {}
    self.commands = []


class TestAdobeSync(unittest.TestCase):
  """Tests for AdobeSync methods."""

  def setUp(self):
    adobe_sync.UNREMOVABLE_USERS = UNREMOVABLE_USERS
    self.adobe_sync = AdobeSyncUnderTest()
    # Override maximum diff output size.
    self.maxDiff = None

  def _deep_sort(self, obj):
    """Recursively sort list or dict nested lists."""

    if isinstance(obj, dict):
      _sorted = {}
      for key in sorted(obj):
        _sorted[key] = self._deep_sort(obj[key])

    elif isinstance(obj, list):
      new_list = []
      for val in obj:
        new_list.append(self._deep_sort(val))
      _sorted = sorted(new_list)

    else:
      _sorted = obj

    return _sorted

  def _check_collection_sizes(self, collection, max_size=10):
    """Recursively checks the provided collection is not larger than max_size.

    Returns True if all collections are less than max_size, otherwise returns False.
    """
    if isinstance(collection, dict):
      if len(collection) > max_size:
        return False
      for value in collection.values():
        if not self._check_collection_sizes(value, max_size):
          return False
    elif isinstance(collection, list):
      if len(collection) > max_size:
        return False
      for value in collection:
        if not self._check_collection_sizes(value, max_size):
          return False

    return True

  def test_compare_group_memberships(self):
    """Test for AdobeSync.compare_group_memberships().

    This method is all about comparing the AD group memberships with the products assigned in the
    portal.
    """
    self.adobe_sync.portal_users = PORTAL_USERS

    # Running the method causes two internal dicts to be updated:
    # user_mods_additions
    # user_mods_subtractions
    self.adobe_sync.compare_group_memberships(AD_GROUPS)

    self.assertEqual(self._deep_sort(USER_MODS_ADDITIONS),
                     self._deep_sort(self.adobe_sync.user_mods_additions))
    self.assertEqual(self._deep_sort(USER_MODS_SUBTRACTIONS),
                     self._deep_sort(self.adobe_sync.user_mods_subtractions))

  def test_generate_portal_commands(self):
    """Test for AdobeSync.generate_portal_commands().

    We're looking for a well-formed command dict as the output.
    """
    self.adobe_sync.portal_users = PORTAL_USERS
    self.adobe_sync.user_mods_additions = USER_MODS_ADDITIONS
    self.adobe_sync.user_mods_subtractions = USER_MODS_SUBTRACTIONS

    self.adobe_sync.generate_portal_commands(EMAIL_TO_USER_DETAILS)
    self.assertEqual(self._deep_sort(self.adobe_sync.commands), self._deep_sort(COMMANDS))

  def test_preprocess_commands(self):
    """Test for AdobeSync.preprocess_commands()."""
    self.adobe_sync.commands = COMMANDS
    chunked_commands = self.adobe_sync.preprocess_commands()
    for commands in chunked_commands:
      import pprint
      pprint.pprint(commands)
      self.assertTrue(self._check_collection_sizes(commands),
                      msg='Command contains a collection which is too large.')


# Test cases covered by this data:
# - A user, not previously on the portal, is added to an AD group (user1).
# - A user, already on the portal, is added to another AD group (user2).
# - A user, already on the portal, is removed from an AD group (user3).
# - A user, already on the portal, is removed from all AD groups (user4).
# - A user is added to more than 10 AD groups (user5).
# - A user is removed from more than 10 AD groups (but not from all AD groups) (user6).
# - A user is both removed from one AD group and added to another AD group (user 7).
# - Make sure an unremovable user cannot be removed if they are removed from all AD groups (user 8).
# - A user is removed from more than 10 groups, and added to more than 10 groups (user 9).

UNREMOVABLE_USERS = ['user8@metacrawler.com']

AD_GROUPS = {
    'test_product_01': ['user1@netscape.com', 'user2@webcrawler.com'],
    'test_product_02': ['user2@webcrawler.com', 'user3@infoseek.com'],
    'test_product_03': ['user5@excite.com', 'user6@compuserve.com', 'user9@slashdot.org'],
    'test_product_04': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_05': ['user5@excite.com', 'user7@lycos.com', 'user9@slashdot.org'],
    'test_product_06': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_07': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_08': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_09': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_10': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_11': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_12': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_13': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_14': ['user5@excite.com', 'user9@slashdot.org'],
    'test_product_15': ['user5@excite.com', 'user9@slashdot.org'],
}


PORTAL_USERS = {
    'user2@webcrawler.com': ['test_product_01'],
    'user3@infoseek.com': ['test_product_02', 'test_product_03'],
    'user4@geocities.com': ['test_product_04', 'test_product_05'],
    'user5@excite.com': ['test_product_03'],
    'user6@compuserve.com': ['test_product_03', 'test_product_04', 'test_product_05',
                             'test_product_06', 'test_product_07', 'test_product_08',
                             'test_product_09', 'test_product_10', 'test_product_11',
                             'test_product_12', 'test_product_13', 'test_product_14',
                             'test_product_15'],
    'user7@lycos.com': ['test_product_04'],
    'user8@metacrawler.com': ['test_product_15'],
    'user9@slashdot.org': ['test_product_15', 'test_product_16', 'test_product_17',
                           'test_product_18', 'test_product_19', 'test_product_20',
                           'test_product_21', 'test_product_22', 'test_product_23',
                           'test_product_24', 'test_product_25', 'test_product_26',]
}


EMAIL_TO_USER_DETAILS = {
    'user1@netscape.com': {'firstname': 'Sherlock', 'lastname': 'Holmes'},
    'user2@webcrawler.com': {'firstname': 'John', 'lastname': 'Watson'},
    'user3@infoseek.com': {'firstname': 'Irene', 'lastname': 'Adler'},
    'user4@geocities.com': {'firstname': 'James', 'lastname': 'Moriarty'},
    'user5@excite.com': {'firstname': 'Mycroft', 'lastname': 'Holmes'},
    'user6@compuserve.com': {'firstname': 'Sebastian', 'lastname': 'Moran'},
    'user7@lycos.com': {'firstname': 'Greg', 'lastname': 'Lestrade'},
    'user8@metacrawler.com': {'firstname': 'Charles', 'lastname': 'Magnussen'},
    'user9@slashdot.org': {'firstname': 'Philip', 'lastname': 'Anderson'},
}


USER_MODS_ADDITIONS = {
    'user1@netscape.com': ['test_product_01'],
    'user2@webcrawler.com': ['test_product_02'],
    'user5@excite.com': ['test_product_04', 'test_product_05', 'test_product_06', 'test_product_07',
                         'test_product_08', 'test_product_09', 'test_product_10', 'test_product_11',
                         'test_product_12', 'test_product_13', 'test_product_14',
                         'test_product_15'],
    'user7@lycos.com': ['test_product_05'],
    'user9@slashdot.org': ['test_product_03', 'test_product_04', 'test_product_05',
                           'test_product_06', 'test_product_07', 'test_product_08',
                           'test_product_09', 'test_product_10', 'test_product_11',
                           'test_product_12', 'test_product_13', 'test_product_14'],
}


USER_MODS_SUBTRACTIONS = {
    'user3@infoseek.com': ['test_product_03'],
    'user4@geocities.com': ['test_product_04', 'test_product_05'],
    'user6@compuserve.com': ['test_product_04', 'test_product_05', 'test_product_06',
                             'test_product_07', 'test_product_08', 'test_product_09',
                             'test_product_10', 'test_product_11', 'test_product_12',
                             'test_product_13', 'test_product_14', 'test_product_15'],
    'user7@lycos.com': ['test_product_04'],
    'user8@metacrawler.com': ['test_product_15'],
    'user9@slashdot.org': ['test_product_16', 'test_product_17', 'test_product_18',
                           'test_product_19', 'test_product_20', 'test_product_21',
                           'test_product_22', 'test_product_23', 'test_product_24',
                           'test_product_25', 'test_product_26']
}

COMMANDS = [
    {'user': 'user1@netscape.com',
     'do': [{'createFederatedID': {'country': 'US',
                                   'email': 'user1@netscape.com',
                                   'firstname': 'Sherlock',
                                   'lastname': 'Holmes',
                                   'option': 'ignoreIfAlreadyExists'}},
            {'add': {'product': ['test_product_01']}}]},

    {'user': 'user2@webcrawler.com',
     'do': [{'createFederatedID': {'country': 'US',
                                   'email': 'user2@webcrawler.com',
                                   'firstname': 'John',
                                   'lastname': 'Watson',
                                   'option': 'ignoreIfAlreadyExists'}},
            {'add': {'product': ['test_product_02']}}]},

    {'user': 'user3@infoseek.com',
     'do': [{'remove': {'product': ['test_product_03']}}]},

    {'user': 'user4@geocities.com',
     'do': [{'removeFromOrg': {}}]},

    {'user': 'user5@excite.com',
     'do': [{'createFederatedID': {'country': 'US',
                                   'email': 'user5@excite.com',
                                   'firstname': 'Mycroft',
                                   'lastname': 'Holmes',
                                   'option': 'ignoreIfAlreadyExists'}},
            {'add': {'product': ['test_product_04', 'test_product_05', 'test_product_06',
                                 'test_product_07', 'test_product_08', 'test_product_09',
                                 'test_product_10', 'test_product_11', 'test_product_12',
                                 'test_product_13', 'test_product_14', 'test_product_15']}}]},

    {'user': 'user6@compuserve.com',
     'do': [{'remove': {'product': ['test_product_04', 'test_product_05', 'test_product_06',
                                    'test_product_07', 'test_product_08', 'test_product_09',
                                    'test_product_10', 'test_product_11', 'test_product_12',
                                    'test_product_13', 'test_product_14', 'test_product_15']}}]},

    {'user': 'user7@lycos.com',
     'do': [{'createFederatedID': {'country': 'US',
                                   'email': 'user7@lycos.com',
                                   'firstname': 'Greg',
                                   'lastname': 'Lestrade',
                                   'option': 'ignoreIfAlreadyExists'}},
            {'add': {'product': ['test_product_05']}},
            {'remove': {'product': ['test_product_04']}}]},

    {'user': 'user8@metacrawler.com',
     'do': [{'remove': {'product': ['test_product_15']}}]},

    {'user': 'user9@slashdot.org',
     'do': [{'createFederatedID': {'country': 'US',
                                   'email': 'user9@slashdot.org',
                                   'firstname': 'Philip',
                                   'lastname': 'Anderson',
                                   'option': 'ignoreIfAlreadyExists'}},
            {'add': {'product': ['test_product_03', 'test_product_04', 'test_product_05',
                                 'test_product_06', 'test_product_07', 'test_product_08',
                                 'test_product_09', 'test_product_10', 'test_product_11',
                                 'test_product_12', 'test_product_13', 'test_product_14']}},
            {'remove': {'product': ['test_product_16', 'test_product_17', 'test_product_18',
                                    'test_product_19', 'test_product_20', 'test_product_21',
                                    'test_product_22', 'test_product_23', 'test_product_24',
                                    'test_product_25', 'test_product_26']}}]},
]


if __name__ == '__main__':
  unittest.main()
