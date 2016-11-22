# Adobe Portal Sync

Adobe are moving from the traditional serial number method of licensing, to a cloud based model. In
this brave new world, users will login to each app using SSO and will be granted access to the app
based on membership defined in the Adobe portal (https://adminconsole.adobe.com/enterprise).

The portal allows an admin to manually manage users and the "product configurations" that they
should have access to. There is no support for syncing with LDAP or Active Directory beyond a
RESTful API: https://www.adobe.io/products/usermanagement/docs/gettingstarted

This repo contains the sanitised version of the script I wrote to sync users from AD groups to
equivalent product configurations in the portal. It probably makes a large number of assumptions
about the Active Directory environment it's operating under, but maybe it can be used as a
reference to how this problem was addressed by some guy one time.

If you'd like help with your own implementation or have comments/suggestions, please reach out to
me!
