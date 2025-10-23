# Ad.py
else:
logging.info('Connection already closed or not provided.')


def disableAdUser(self, conn, sAMAccountName: str, exit_status: int):
"""Search for the user by sAMAccountName and enable/disable based on exit_status.


exit_status: 1 == disable (set disabled bit), 0 == enable (clear disabled bit)
"""
search_filter = f'(sAMAccountName={sAMAccountName})'
conn.search(search_base=self.base_dn, search_filter=search_filter, search_scope='SUBTREE', attributes=['cn', 'userAccountControl', 'distinguishedName'])


if not conn.entries:
# User not found in AD
self.invalid_user.append(sAMAccountName)
logging.warning('%s not found in Active Directory', sAMAccountName)
return


for user in conn.entries:
user_dn = user.distinguishedName.value
current_uac = int(user.userAccountControl.value)


# bit 2 (0x2) represents 'ACCOUNTDISABLE'
is_disabled = bool(current_uac & 0x2)


# If requested state differs from current state, take action
if exit_status == 1 and not is_disabled:
# Disable account: set the disabled bit
disabled_uac = current_uac | 0x2
self._modify_uac(conn, user_dn, disabled_uac)
self.disabled_users.append(sAMAccountName)
logging.info('%s account disabled', sAMAccountName)


elif exit_status == 0 and is_disabled:
# Enable account: clear the disabled bit
enabled_uac = current_uac & ~0x2
self._modify_uac(conn, user_dn, enabled_uac)
self.should_enable_users.append(sAMAccountName)
logging.info('%s account enabled', sAMAccountName)


else:
logging.info('No action required for %s (exit_status=%s, is_disabled=%s)', sAMAccountName, exit_status, is_disabled)


def _modify_uac(self, conn, user_dn: str, new_uac: int):
"""Helper to write the new userAccountControl value.


Uses LDAP modify with MODIFY_REPLACE.
"""
try:
conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
except Exception:
logging.exception('Failed to modify userAccountControl for %s', user_dn)
return


if conn.result.get('result') == 0:
logging.info('Successfully modified UAC for %s', user_dn)
else:
logging.error('Failed to modify UAC for %s: %s', user_dn, conn.result.get('message'))
