# app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE, Tls
from config import Config
import ssl 
import struct

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_dn = f"{Config.DOMAIN}\\{username}"

        try:
            server = Server(Config.LDAP_SERVER, get_info=ALL)
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
            session['username'] = username
            session['password'] = password  # store for reuse in later LDAP ops
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Login failed: {str(e)}', 'danger')

    return render_template('login.html')


def is_admin():
    """Check if the current user is the Administrator user"""
    if 'username' not in session:
        return False
    
    # Only the Administrator user has full access
    # All other users (including members of Administrators group) have view-only access
    return session['username'].lower() == 'administrator'


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get statistics for dashboard
    stats = get_ad_statistics()
    # Check if user is admin
    session['is_admin'] = is_admin()
    return render_template('dashboard.html', stats=stats, is_admin=session['is_admin'])


def get_ad_statistics():
    """Get AD statistics for dashboard display"""
    stats = {
        'total_users': 0,
        'total_groups': 0,
        'total_computers': 0,
        'enabled_users': 0,
        'disabled_users': 0,
        'locked_users': 0
    }
    
    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)
        
        # Count users
        conn.search('OU=LinuxUsers,DC=vvs,DC=com', '(objectClass=user)', SUBTREE,
                    attributes=['userAccountControl', 'lockoutTime'])
        
        stats['total_users'] = len(conn.entries)
        
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if 'userAccountControl' in entry else 512
            lockout_time = int(entry.lockoutTime.value.timestamp()) if 'lockoutTime' in entry and entry.lockoutTime.value else 0
            
            if not (uac & 2):  # Account is enabled
                stats['enabled_users'] += 1
            else:
                stats['disabled_users'] += 1
                
            if lockout_time > 0:
                stats['locked_users'] += 1
        
        # Count groups
        conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', SUBTREE)
        stats['total_groups'] = len(conn.entries)
        
        # Count computers
        conn.search(Config.BASE_DN, '(objectClass=computer)', attributes=['cn'])
        stats['total_computers'] = len(conn.entries)
        
        conn.unbind()
        
    except Exception as e:
        print(f"Error getting statistics: {str(e)}")
    
    return stats


@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can create users.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form['password']
        display_name = request.form['display_name'].strip()
        email = request.form['email'].strip()
        uid_number = request.form['uid_number'].strip()
        gid_number = request.form['gid_number'].strip()

        user_dn = f"CN={new_username},OU=LinuxUsers,DC=vvs,DC=com"

        try:
            tls_config = Tls(validate=ssl.CERT_NONE)
            server = Server(
                f"ldaps://{Config.LDAP_SERVER}", port=636,
                use_ssl=True, get_info=ALL, tls=tls_config
            )

            conn = Connection(
                server,
                user=f"{Config.DOMAIN}\\{session['username']}",
                password=session.get('password'),
                authentication=NTLM,
                auto_bind=True
            )

            # 🔍 Check if username already exists
            conn.search('OU=LinuxUsers,DC=vvs,DC=com', f'(sAMAccountName={new_username})', attributes=['sAMAccountName'])
            if conn.entries:
                flash(f'❌ Username "{new_username}" already exists.', 'danger')
                return render_template('create_user.html', is_admin=session.get('is_admin', False))

            # 🔍 Check if uidNumber already exists
            conn.search('OU=LinuxUsers,DC=vvs,DC=com', f'(uidNumber={uid_number})', attributes=['uidNumber'])
            if conn.entries:
                flash(f'❌ uidNumber "{uid_number}" is already used.', 'danger')
                return render_template('create_user.html', is_admin=session.get('is_admin', False))

            # ✅ Add user
            conn.add(user_dn, ['top', 'person', 'organizationalPerson', 'user'], {
                'cn': new_username,
                'sAMAccountName': new_username,
                'userPrincipalName': f"{new_username}@{Config.DOMAIN}",
                'displayName': display_name,
                'mail': email,
                'uidNumber': uid_number,
                'gidNumber': gid_number,
                'unixHomeDirectory': f"/home/users/{new_username}"
            })

            # ✅ Set password
            unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
            conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})

            # ✅ Enable user
            conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

            flash(f'✅ User "{new_username}" created successfully.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f'❌ Error creating user: {str(e)}', 'danger')

    return render_template('create_user.html', is_admin=session.get('is_admin', False))


@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can create groups.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        group_name = request.form['group_name'].strip()
        gid_number = request.form.get('gid_number', '').strip()
        description = request.form.get('description', '').strip()

        group_dn = f"CN={group_name},OU=LinuxGroups,DC=vvs,DC=com"

        try:
            tls_config = Tls(validate=ssl.CERT_NONE)
            server = Server(
                f"ldaps://{Config.LDAP_SERVER}", port=636,
                use_ssl=True, get_info=ALL, tls=tls_config
            )

            conn = Connection(
                server,
                user=f"{Config.DOMAIN}\\{session['username']}",
                password=session.get('password'),
                authentication=NTLM,
                auto_bind=True
            )

            # 🔍 Check if group already exists
            conn.search('OU=LinuxGroups,DC=vvs,DC=com', f'(sAMAccountName={group_name})', attributes=['sAMAccountName'])
            if conn.entries:
                flash(f'❌ Group "{group_name}" already exists.', 'danger')
                return render_template('create_group.html', is_admin=session.get('is_admin', False))

            # 🔍 Check if gidNumber already exists
            if gid_number:
                conn.search('OU=LinuxGroups,DC=vvs,DC=com', f'(gidNumber={gid_number})', attributes=['gidNumber'])
                if conn.entries:
                    flash(f'❌ gidNumber "{gid_number}" is already used.', 'danger')
                    return render_template('create_group.html', is_admin=session.get('is_admin', False))

            # ✅ Add group
            attributes = {
                'sAMAccountName': group_name
            }

            if gid_number:
                attributes['gidNumber'] = gid_number

            if description:
                attributes['description'] = description

            conn.add(group_dn, ['top', 'group'], attributes)

            if conn.result['result'] == 0:
                flash(f'✅ Group "{group_name}" created successfully.', 'success')
            else:
                flash(f'❌ Failed to create group: {conn.result["message"]}', 'danger')

            conn.unbind()
            return redirect(url_for('create_group'))

        except Exception as e:
            flash(f'❌ Error creating group: {str(e)}', 'danger')

    return render_template('create_group.html', is_admin=session.get('is_admin', False))




@app.route('/users')
def list_users():
    if 'username' not in session:
        return redirect(url_for('login'))

    users = []
    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        # Only search in LinuxUsers OU
        conn.search('OU=LinuxUsers,DC=vvs,DC=com', '(objectClass=user)', SUBTREE,
                    attributes=['sAMAccountName', 'displayName', 'mail', 'uidNumber', 'userAccountControl'])

        for entry in conn.entries:
            uac = int(entry.userAccountControl.value) if 'userAccountControl' in entry else 512
            users.append({
                'username': entry.sAMAccountName.value,
                'name': entry.displayName.value,
                'email': entry.mail.value if 'mail' in entry else '',
                'uid': entry.uidNumber.value if 'uidNumber' in entry else '',
                'enabled': not (uac & 2)  # Check if account is enabled
            })

    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')

    return render_template('users.html', users=users, is_admin=session.get('is_admin', False))

@app.route('/user/<username>/reset_password', methods=['GET', 'POST'])
def reset_password(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can reset passwords.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        user_dn = f"CN={username},OU=LinuxUsers,DC=vvs,DC=com"

        try:
            tls_config = Tls(validate=ssl.CERT_NONE)
            server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
            conn = Connection(
                server,
                user=f"{Config.DOMAIN}\\{session['username']}",
                password=session.get('password'),
                authentication=NTLM,
                auto_bind=True
            )

            # ✅ Enable user (if not already)
            conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})

            # ✅ Set new password
            unicode_pwd = f'"{new_password}"'.encode('utf-16-le')
            conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_pwd])]})

            if conn.result['result'] == 0:
                flash(f'✅ Password reset successfully for {username}', 'success')
            else:
                flash(f'❌ LDAP Error: {conn.result["message"]}', 'danger')

        except Exception as e:
            print(f"[ERROR] Reset password for {username}: {e}")  # Show in logs
            flash(f'❌ Error resetting password: {str(e)}', 'danger')

        return redirect(url_for('list_users'))

    return render_template('reset_password.html', username=username, is_admin=session.get('is_admin', False))


@app.route('/user/<username>/edit', methods=['GET', 'POST'])
def edit_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can edit users.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session.get('password'),
            authentication=NTLM,
            auto_bind=True
        )

        # ✅ Search by sAMAccountName
        search_base = f"OU=LinuxUsers,{Config.BASE_DN}"
        search_filter = f"(sAMAccountName={username})"

        conn.search(search_base=search_base, search_filter=search_filter, attributes=[
            'displayName', 'mail', 'telephoneNumber', 'uidNumber', 'gidNumber'
        ])

        if not conn.entries:
            flash('❌ User not found.', 'danger')
            return redirect(url_for('list_users'))

        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn  # ✅ Get correct DN from search result

        if request.method == 'POST':
            display_name = request.form['displayName']
            email = request.form['mail']
            phone = request.form['telephoneNumber']

            changes = {
                'displayName': [(MODIFY_REPLACE, [display_name])],
                'mail': [(MODIFY_REPLACE, [email])],
                'telephoneNumber': [(MODIFY_REPLACE, [phone])]
            }

            conn.modify(user_dn, changes)

            if conn.result['result'] == 0:
                flash(f'✅ User "{username}" updated successfully.', 'success')
                return redirect(url_for('user_details', username=username))
            else:
                flash(f'❌ LDAP Error: {conn.result["message"]}', 'danger')

        # GET: Pre-fill the form
        user = {
            'display_name': str(user_entry.displayName) if 'displayName' in user_entry else '',
            'email': str(user_entry.mail) if 'mail' in user_entry else '',
            'phone': str(user_entry.telephoneNumber) if 'telephoneNumber' in user_entry else '',
            'uid_number': str(user_entry.uidNumber) if 'uidNumber' in user_entry else '',
            'gid_number': str(user_entry.gidNumber) if 'gidNumber' in user_entry else ''
        }

        return render_template('edit_user.html', username=username, user=user, is_admin=session.get('is_admin', False))

    except Exception as e:
        import traceback
        print(f"[ERROR] Edit user {username}:\n", traceback.format_exc())
        flash(f'❌ Error editing user: {str(e)}', 'danger')
        return redirect(url_for('user_details', username=username))




@app.route('/user/<username>', methods=['GET', 'POST'])
def user_details(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)

        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        search_base = f"OU=LinuxUsers,{Config.BASE_DN}"
        search_filter = f"(sAMAccountName={username})"

        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=[
                'displayName', 'mail', 'uidNumber', 'gidNumber',
                'userAccountControl', 'lockoutTime', 'userWorkstations'  # ✅
            ]
        )

        if not conn.entries:
            flash('User not found.', 'warning')
            return redirect(url_for('list_users'))

        entry = conn.entries[0]

        display_name = str(entry.displayName) if 'displayName' in entry else ''
        email = str(entry.mail) if 'mail' in entry else ''
        uid = str(entry.uidNumber) if 'uidNumber' in entry else ''
        gid = str(entry.gidNumber) if 'gidNumber' in entry else ''
        uac = int(entry.userAccountControl.value) if 'userAccountControl' in entry else 512
        lockout_time = int(entry.lockoutTime.value.timestamp()) if 'lockoutTime' in entry and entry.lockoutTime.value else 0
        allowed_computers = str(entry.userWorkstations) if 'userWorkstations' in entry else ''

        user = {
            'username': username,
            'display_name': display_name,
            'email': email,
            'uid_number': uid,
            'gid_number': gid,
            'enabled': not (uac & 2),
            'locked': lockout_time > 0,
            'allowed_computers': allowed_computers  # ✅
        }

        return render_template('user_details.html', user=user, is_admin=session.get('is_admin', False))

    except Exception as e:
        import traceback
        print("Error in user_details():", traceback.format_exc())
        flash(f'Error loading user details: {str(e)}', 'danger')
        return redirect(url_for('list_users'))

@app.route('/user/<username>/unlock', methods=['GET', 'POST'])
def unlock_account(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can unlock accounts.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        # Search user by sAMAccountName
        conn.search(
            search_base=f"OU=LinuxUsers,{Config.BASE_DN}",
            search_filter=f"(sAMAccountName={username})",
            attributes=['distinguishedName']
        )

        if not conn.entries:
            flash(f"❌ User '{username}' not found.", 'danger')
            return redirect(url_for('user_details', username=username))

        user_dn = conn.entries[0].entry_dn

        conn.modify(user_dn, {'lockoutTime': [(MODIFY_REPLACE, ['0'])]})

        if conn.result['result'] == 0:
            flash(f"✅ Account '{username}' unlocked successfully.", 'success')
        else:
            flash(f"❌ Failed to unlock account: {conn.result['message']}", 'danger')

    except Exception as e:
        flash(f"❌ Error unlocking account: {str(e)}", 'danger')

    return redirect(url_for('user_details', username=username))


@app.route('/user/<username>/disable', methods=['GET', 'POST'])
def disable_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can disable users.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        # Search user by sAMAccountName
        conn.search(
            search_base=f"OU=LinuxUsers,{Config.BASE_DN}",
            search_filter=f"(sAMAccountName={username})",
            attributes=['distinguishedName']
        )

        if not conn.entries:
            flash(f"❌ User '{username}' not found.", 'danger')
            return redirect(url_for('user_details', username=username))

        user_dn = conn.entries[0].entry_dn

        # Get current userAccountControl value for debugging
        conn.search(user_dn, '(objectClass=*)', attributes=['userAccountControl'])
        current_uac = int(conn.entries[0].userAccountControl.value) if conn.entries else 512
        
        # Disable the account (set bit 2)
        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [514])]})  # 514 = NORMAL_ACCOUNT + ACCOUNTDISABLE

        if conn.result['result'] == 0:
            # Verify the change was applied
            conn.search(user_dn, '(objectClass=*)', attributes=['userAccountControl'])
            new_uac = int(conn.entries[0].userAccountControl.value) if conn.entries else 512
            
            if new_uac & 2:  # Check if ACCOUNTDISABLE bit is set
                flash(f"✅ User '{username}' disabled successfully. (UAC: {current_uac} → {new_uac})", 'success')
            else:
                flash(f"⚠️ User '{username}' disable may have failed. UAC: {current_uac} → {new_uac}", 'warning')
        else:
            flash(f"❌ Failed to disable user: {conn.result['message']} (Code: {conn.result['result']})", 'danger')

    except Exception as e:
        flash(f"❌ Error disabling user: {str(e)}", 'danger')

    return redirect(url_for('user_details', username=username))


@app.route('/user/<username>/enable', methods=['GET', 'POST'])
def enable_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can enable users.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        # Search user by sAMAccountName
        conn.search(
            search_base=f"OU=LinuxUsers,{Config.BASE_DN}",
            search_filter=f"(sAMAccountName={username})",
            attributes=['distinguishedName']
        )

        if not conn.entries:
            flash(f"❌ User '{username}' not found.", 'danger')
            return redirect(url_for('user_details', username=username))

        user_dn = conn.entries[0].entry_dn

        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})  # 512 = ENABLED (NORMAL_ACCOUNT)

        if conn.result['result'] == 0:
            flash(f"✅ User '{username}' enabled successfully.", 'success')
        else:
            flash(f"❌ Failed to enable user: {conn.result['message']}", 'danger')

    except Exception as e:
        flash(f"❌ Error enabling user: {str(e)}", 'danger')

    return redirect(url_for('user_details', username=username))


@app.route('/user/<username>/delete', methods=['GET', 'POST'])
def delete_user(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can delete users.', 'danger')
        return redirect(url_for('dashboard'))

    user_dn = f"CN={username},OU=LinuxUsers,{Config.BASE_DN}"

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        conn.delete(user_dn)

        if conn.result['result'] == 0:
            flash(f"✅ User '{username}' deleted successfully.", 'success')
        else:
            flash(f"❌ Failed to delete user: {conn.result['message']}", 'danger')

    except Exception as e:
        flash(f"❌ Error deleting user: {str(e)}", 'danger')

    return redirect(url_for('list_users'))



@app.route('/groups')
def list_groups():
    if 'username' not in session:
        return redirect(url_for('login'))

    groups = []
    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', SUBTREE,
                    attributes=['cn', 'description', 'gidNumber'])

        for entry in conn.entries:
            groups.append({
                'name': entry.cn.value,
                'description': entry.description.value if 'description' in entry else '',
                'gid': entry.gidNumber.value if 'gidNumber' in entry else ''
            })

    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')

    return render_template('groups.html', groups=groups, is_admin=session.get('is_admin', False))

@app.route('/group_members')
def group_members():
    if 'username' not in session:
        return redirect(url_for('login'))

    group_info = {}

    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        # Search for all groups in LinuxGroups OU
        conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', attributes=['cn', 'member'])

        for entry in conn.entries:
            group_name = entry.cn.value
            members_dns = entry.member.values if 'member' in entry else []
            members_usernames = []

            for member_dn in members_dns:
                # Look up the CN for each member DN
                conn.search(member_dn, '(objectClass=user)', attributes=['sAMAccountName'])
                if conn.entries:
                    members_usernames.append(conn.entries[0].sAMAccountName.value)

            group_info[group_name] = members_usernames

    except Exception as e:
        flash(f"❌ Error fetching group members: {str(e)}", "danger")

    return render_template('group_members.html', group_info=group_info, is_admin=session.get('is_admin', False))


@app.route('/add_to_group', methods=['GET', 'POST'])
def add_to_group():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can add users to groups.', 'danger')
        return redirect(url_for('dashboard'))

    users = []
    groups = []

    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        # Fetch users from LinuxUsers OU
        conn.search('OU=LinuxUsers,DC=vvs,DC=com', '(objectClass=user)', attributes=['cn'])
        users = [entry.cn.value for entry in conn.entries]

        # Fetch groups from LinuxGroups OU
        conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', attributes=['cn'])
        groups = [entry.cn.value for entry in conn.entries]

        if request.method == 'POST':
            selected_user = request.form['user']
            selected_group = request.form['group']

            user_dn = f"CN={selected_user},OU=LinuxUsers,DC=vvs,DC=com"
            group_dn = f"CN={selected_group},OU=LinuxGroups,DC=vvs,DC=com"

            # Add user to group
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})

            flash(f"✅ User '{selected_user}' added to group '{selected_group}'.", 'success')
            return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')

    return render_template('add_to_group.html', users=users, groups=groups, is_admin=session.get('is_admin', False))

@app.route('/remove_from_group', methods=['GET', 'POST'])
def remove_from_group():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can remove users from groups.', 'danger')
        return redirect(url_for('dashboard'))

    users = []
    groups = []

    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        conn.search('OU=LinuxUsers,DC=vvs,DC=com', '(objectClass=user)', attributes=['cn'])
        users = [entry.cn.value for entry in conn.entries]

        conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', attributes=['cn'])
        groups = [entry.cn.value for entry in conn.entries]

        if request.method == 'POST':
            selected_user = request.form['user']
            selected_group = request.form['group']

            user_dn = f"CN={selected_user},OU=LinuxUsers,DC=vvs,DC=com"
            group_dn = f"CN={selected_group},OU=LinuxGroups,DC=vvs,DC=com"

            # Fetch current group members
            conn.search(group_dn, '(objectClass=group)', attributes=['member'])
            if not conn.entries:
                flash("Group not found.", "danger")
                return redirect(url_for('remove_from_group'))

            group_entry = conn.entries[0]
            current_members = group_entry.member.values if 'member' in group_entry else []

            if user_dn not in current_members:
                flash(f"User {selected_user} is not a member of {selected_group}.", "warning")
                return redirect(url_for('remove_from_group'))

            # Attempt to remove the user
            success = conn.modify(group_dn, {
                'member': [(MODIFY_DELETE, [user_dn])]
            })

            if success:
                flash(f"✅ User '{selected_user}' removed from group '{selected_group}'.", 'success')
            else:
                flash(f"❌ Failed to remove user. {conn.result['message']}", 'danger')

            return redirect(url_for('remove_from_group'))

    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')

    return render_template('remove_from_group.html', users=users, groups=groups, is_admin=session.get('is_admin', False))


@app.route('/computers')
def list_computers():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)

        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        # Search for all objects with objectClass=computer
        conn.search(
            search_base=Config.BASE_DN,  # Search entire domain
            search_filter='(objectClass=computer)',
            attributes=['cn', 'dNSHostName', 'operatingSystem', 'lastLogonTimestamp']
        )

        computers = []
        for entry in conn.entries:
            computer = {
                'name': str(entry.cn),
                'hostname': str(entry.dNSHostName) if 'dNSHostName' in entry else '',
                'os': str(entry.operatingSystem) if 'operatingSystem' in entry else '',
                'last_logon': str(entry.lastLogonTimestamp) if 'lastLogonTimestamp' in entry else ''
            }
            computers.append(computer)

        return render_template('computers.html', computers=computers, is_admin=session.get('is_admin', False))

    except Exception as e:
        flash(f"Error retrieving computer accounts: {str(e)}", 'danger')
        return redirect(url_for('dashboard'))

@app.route('/user/<username>/logonto', methods=['GET', 'POST'])
def set_logon_to(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user is admin
    if not session.get('is_admin', False):
        flash('❌ Access denied. Only administrators can set logon restrictions.', 'danger')
        return redirect(url_for('dashboard'))

    user_dn = f"CN={username},OU=LinuxUsers,{Config.BASE_DN}"

    try:
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(f"ldaps://{Config.LDAP_SERVER}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)
        conn = Connection(
            server,
            user=f"{Config.DOMAIN}\\{session['username']}",
            password=session['password'],
            authentication=NTLM,
            auto_bind=True
        )

        # Get available computers
        conn.search(Config.BASE_DN, '(objectClass=computer)', attributes=['cn'])
        all_computers = [str(entry.cn) for entry in conn.entries]

        # Get current userWorkstations
        conn.search(user_dn, '(objectClass=person)', attributes=['userWorkstations'])
        current = str(conn.entries[0].userWorkstations) if conn.entries and 'userWorkstations' in conn.entries[0] else ''

        selected = current.split(',') if current else []

        if request.method == 'POST':
            selected_computers = request.form.getlist('computers')  # list of hostnames
            
            if selected_computers:
                # If computers are selected, update the attribute
                new_value = ','.join(selected_computers)
                conn.modify(user_dn, {'userWorkstations': [(MODIFY_REPLACE, [new_value])]})
            else:
                # If no computers selected, delete the attribute
                conn.modify(user_dn, {'userWorkstations': [(MODIFY_DELETE, [])]})

            if conn.result['result'] == 0:
                flash("✅ Logon Workstations updated.", 'success')
            else:
                flash(f"❌ LDAP Error: {conn.result['message']}", 'danger')

            return redirect(url_for('user_details', username=username))

        return render_template('logon_to.html', username=username, computers=all_computers, selected=selected, is_admin=session.get('is_admin', False))

    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
        return redirect(url_for('user_details', username=username))


@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))

    result = None
    search_type = request.form.get('search_type')
    keyword = request.form.get('keyword')

    try:
        server = Server(Config.LDAP_SERVER, get_info=ALL)
        conn = Connection(server,
                          user=f"{Config.DOMAIN}\\{session['username']}",
                          password=session.get('password'),
                          authentication=NTLM,
                          auto_bind=True)

        if request.method == 'POST':
            if search_type == 'user':
                # Find groups that the user is a member of
                user_dn = f"CN={keyword},OU=LinuxUsers,DC=vvs,DC=com"
                conn.search('OU=LinuxGroups,DC=vvs,DC=com', '(objectClass=group)', attributes=['cn', 'member'])

                groups = []
                for entry in conn.entries:
                    members = entry.member.values if 'member' in entry else []
                    if user_dn in members:
                        groups.append(entry.cn.value)

                result = {'type': 'user', 'keyword': keyword, 'groups': groups}

            elif search_type == 'group':
                group_dn = f"CN={keyword},OU=LinuxGroups,DC=vvs,DC=com"
                conn.search(group_dn, '(objectClass=group)', attributes=['member'])

                users = []
                if conn.entries:
                    member_dns = conn.entries[0].member.values if 'member' in conn.entries[0] else []
                    for dn in member_dns:
                        conn.search(dn, '(objectClass=user)', attributes=['sAMAccountName'])
                        if conn.entries:
                            users.append(conn.entries[0].sAMAccountName.value)

                result = {'type': 'group', 'keyword': keyword, 'users': users}

    except Exception as e:
        flash(f"❌ Error: {str(e)}", 'danger')

    return render_template('search.html', result=result, is_admin=session.get('is_admin', False))


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('password', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
