# Model module
module Model
  # Create an instance of the database
  #
  # @param [String] path The path to the database file
  #
  # @return [SQLite3::Database]
  def connect_db(path = 'db/database.db')
    db = SQLite3::Database.new(path)
    db.results_as_hash = true

    return db
  end

  # Find a user by id
  #
  # @param [Integer] user_id The ID of the user
  #
  # @return [Hash]
  #   * :id [Integer] The ID of the user
  #   * :username [String] The username of the user
  #   * :pwd_digest [String] The hashed password of the user
  def get_user_by_id(user_id)
    db = connect_db()

    return db.execute('SELECT * FROM users WHERE id = ?', user_id).first
  end

  # Find a user by username
  #
  # @param [String] username The username of the user
  #
  # @return [Hash]
  #   * :id [Integer] The ID of the user
  #   * :username [String] The username of the user
  #   * :pwd_digest [String] The hashed password of the user
  def get_user_by_username(username)
    db = connect_db()

    return db.execute('SELECT * FROM users WHERE username = ?', username).first
  end

  # Validate user credentials and return user_id or return error if credentials were invalid
  #
  # @param [String] username Username
  # @param [String] password Password
  #
  # @return [Hash] if an error occurred
  #   * :error [Boolean] Whether or not an error occured
  #   * :validation_errors [Array<Hash>] An array of errors
  #     * :param [String] Name of the parameter
  #     * :errors [Array<String>] An array of error codes
  # @return [Integer] The id of the user if credentials were valid
  def login_user(username, password)
    db = connect_db()

    # get user with username
    user = db.execute('SELECT * FROM users WHERE username = ?', username).first

    if user
      # compare password
      pwd_digest = user['pwd_digest']

      if BCrypt::Password.new(pwd_digest) == password
        # login user
        return user['id']
      else
        return {
                 error: true,
                 validation_errors: [
                   {
                     param: 'password',
                     errors: [
                       'invalid'
                     ]
                   }
                 ]
               }
      end
    else
      return {
               error: true,
               validation_errors: [
                 {
                   param: 'username',
                   errors: [
                     'not-found'
                   ]
                 }
               ]
             }
    end

    return {
             error: false,
             validation_errors: []
           }
  end

  # Create a user from username and password and return the ID of the user or return error when validation failed
  #
  # @param [String] username Username
  # @param [String] password Password
  # @param [String] confirm_password Password confirmation. Should equal passowrd.
  #
  # @return [Hash]
  #   * :error [Boolean] Whether or not an error occured
  #   * :validation_errors [Array<Hash>] An array of errors
  #     * :param [String] Name of the parameter
  #     * :errors [Array<String>] An array of error codes
  # @return [Integer] ID of the user if function args were valid
  def register_user(username, password, confirm_password)
    # validate password
    if !(password == confirm_password)
      # show error message: passwords not matching
      return {
               error: true,
               validation_errors: [
                 {
                   param: 'password',
                   errors: [
                     'not-matching'
                   ]
                 },
                 {
                   param: 'confirm',
                   errors: [
                     'not-matching'
                   ]
                 }
               ]
             }
    end

    if (username.length < 4)
      return {
               error: true,
               validation_errors: [
                 {
                   param: 'username',
                   errors: [
                     'too-short'
                   ]
                 }
               ]
             }
    end

    if (password.length < 8 && !(password.match(/\w+/) && password.match(/\d+/)))
      return {
               error: true,
               validation_errors: [
                 {
                   param: 'password',
                   errors: [
                     'too-weak'
                   ]
                 }
               ]
             }
    end

    db = connect_db()

    # check for existing users
    user = db.execute('SELECT * FROM users WHERE username = ?', username).first
    if user
      # show error message: user exists already
      return {
               error: true,
               validation_errors: [
                 {
                   param: 'username',
                   errors: [
                     'not-unique'
                   ]
                 }
               ]
             }
    end

    # one-way encrypt password
    pwd_digest = BCrypt::Password.create(password)

    # create new user
    db.execute('INSERT INTO users (username, pwd_digest) VALUES (?, ?)', username, pwd_digest)

    # get id of new user
    new_user = db.execute('SELECT id FROM users WHERE username = ?', username).first

    return new_user['id']
  end

  # Create a chat group
  #
  # @param [Integer] user_id The id of the user creator
  # @param [String] group_name The name of the group
  # @param [String] color The group color
  #
  # @return [nil]
  def create_group(user_id, group_name, color = nil)
    db = connect_db()

    # create group
    if color
      db.execute('INSERT INTO chat_groups (name, creator, color) VALUES (?, ?, ?)', group_name, user_id, color)
    else
      db.execute('INSERT INTO chat_groups (name, creator) VALUES (?, ?)', group_name, user_id)
    end

    group_id = db.last_insert_row_id

    add_member_to_group(group_id, user_id)
  end

  # Find a chat group by id
  #
  # @param [Integer] group_id The id of the group
  #
  # @return [Hash]
  #   * :id [Integer] The ID of the chat group
  #   * :name [String] The name of the chat group
  #   * :creator [Integer] The ID of the chat group
  def get_group_by_id(group_id)
    db = connect_db()

    group = db.execute('SELECT * FROM chat_groups WHERE id = ?', group_id.to_i).first

    return group
  end

  # Update name of a char group by id
  #
  # @param [Integer] group_id The id of the group
  # @param [String] name The new name of the group
  # @param [String] color The new color of the group
  #
  # @return [nil]
  def update_group(group_id, name, color = nil)
    db = connect_db()

    if color
      db.execute('UPDATE
                  chat_groups
                SET name = ?, color = ?
                WHERE id = ?', name, color, group_id)
    else
      db.execute('UPDATE
                  chat_groups
                SET name = ?
                WHERE id = ?', name, group_id)
    end
  end

  # Delete group by id
  #
  # @param [Integer] group_id The id of the group
  #
  # @return [nil]
  def delete_group(group_id)
    db = connect_db()

    db.execute('DELETE FROM chat_groups WHERE id = ?', group_id)
  end

  # Create a message in a chat group
  #
  # @param [Integer] group_id The id of the group
  # @param [Integer] user_id The id of the user
  # @param [String] message The text that the user sent
  #
  # @return [nil]
  def create_message_in_group(group_id, user_id, message)
    db = connect_db()

    # create message
    db.execute('INSERT INTO messages (message, group_id, user_id) VALUES (?, ?, ?)', message, group_id, user_id)
    message_id = db.last_insert_row_id

    return get_message_by_id(message_id)
  end

  # Get all messages in a group by id
  #
  # @param [Integer] group_id The id of the group
  #
  # @return [Array<Hash>]
  #   * :id [Integer] The ID of the message
  #   * :message [String] The text message
  #   * :group_id [Integer] The ID of the group where the message was posted
  #   * :user_id [Integer] The ID of the user that sent the message
  def get_messages_in_group(group_id)
    db = connect_db()

    # get messages from group with sender username
    messages = db.execute('SELECT 
                            messages.id,
                            users.username,
                            messages.message,
                            messages.user_id
                          FROM messages
                          LEFT JOIN users
                          ON messages.user_id = users.id
                          WHERE group_id = ?
                          ', group_id)
    return messages
  end

  # Get message by id
  #
  # @param [Integer] id The ID of the message
  #
  # @return [Hash]
  #   * :id [Integer] The ID of the message
  #   * :message [String] The text message
  #   * :group_id [Integer] The ID of the group where the message was posted
  #   * :user_id [Integer] The ID of the user that sent the message
  def get_message_by_id(id)
    db = connect_db()

    message = db.execute('SELECT
                            messages.*,
                            users.username
                          FROM messages
                          LEFT JOIN users
                          ON users.id = messages.user_id
                          WHERE messages.id = ?', id).first

    return message
  end

  # def update_message_in_group(group_id)
  # TODO
  # end

  # Delete a message by id
  #
  # @param [Integer] message_id The ID of the message
  #
  # @return [nil]
  def delete_message(group_id, message_id, user_id)
    db = connect_db()

    message = get_message_by_id(message_id)
    group = get_group_by_id(group_id)

    # user is not group owner or creator of the message
    if (message['user_id'] != user_id && group['creator'] != user_id)
      raise "You don't have permissions to delete message with id #{message_id}"
    end

    db.execute('DELETE FROM messages WHERE id = ?', message_id)
  end

  # Get all the groups that the user is a member of
  #
  # @param [Integer] user_id The ID of the user
  #
  # @return [Array<Hash>]
  #   * :id [Integer] The ID of the user
  #   * :username [String] The username
  #   * :pwd_digest [String] The hashed password
  def get_groups_of_user(user_id)
    db = connect_db()

    if (!user_id)
      # return empty if not logged in
      return []
    end

    # get groups where user is a member of
    groups = db.execute('SELECT 
                          *,
                          chat_groups.id as id
                        FROM
                          chat_groups
                        INNER JOIN groups_users
                        ON (chat_groups.id = groups_users.group_id)
                        WHERE groups_users.user_id = ?
                        ', user_id)

    return groups
  end

  # Returns whether or not a username is already taken
  #
  # @param [String] username Username
  #
  # @return [Boolean]
  def username_exists(username)
    db = connect_db()

    # get the user id of user with username
    user = db.execute('SELECT id FROM users WHERE username = ?', username).first

    return user ? true : false
  end

  # Returns whether or not a user is already a member of a group
  #
  # @param [Integer] group_id The ID of the group
  # @param [Integer] user_id The ID of the user
  #
  # @return [Boolean]
  def user_exists_in_group(group_id, user_id)
    db = connect_db()

    is_member = db.execute('SELECT
                *
                FROM groups_users
                WHERE user_id = ? AND group_id = ?
                ', user_id, group_id.to_i).first

    return is_member ? true : false
  end

  # Add a user as a member to a group
  #
  # @param [Integer] group_id The ID of the group
  # @param [String] username_or_id The username or id of the user to add to the chat group
  #
  # @return [nil]
  def add_member_to_group(group_id, username_or_id)
    db = connect_db()

    new_member_username = username_or_id

    if (username_or_id.is_a?(Integer))
      user = db.execute('SELECT username FROM users WHERE id = ?', username_or_id).first

      if (!user)
        raise "No user with id #{username_or_id}"
      else
        new_member_username = user['username']
      end
    end

    # get the user id of user with username
    if (!username_exists(new_member_username))
      # display error message
      raise "No user found with username #{new_member_username}"
    end

    user = get_user_by_username(new_member_username)
    user_id = user['id']

    if (user_exists_in_group(group_id, user_id))
      # display error message
      raise 'User is already a member of the group'
    end

    db.execute('INSERT INTO groups_users (user_id, group_id) VALUES (?, ?)', user_id, group_id)

    return nil
  end

  # Returns all members in a group
  #
  # @param [Integer] group_id The ID of the group
  #
  # @return [Array<Hash>]
  #   * :id [Integer] The ID of the user
  #   * :username [String] The username of the user
  #   * :pwd_digest [String] The hashed password of the user
  def get_members_in_group(group_id)
    if (!group_id)
      return []
    end

    db = connect_db()

    members = db.execute('SELECT
                            users.id,
                            users.username,
                            users_group_roles.group_role_id
                          FROM
                            users
                          INNER JOIN groups_users
                            ON groups_users.user_id = users.id
                          LEFT JOIN users_group_roles
                            ON users_group_roles.user_id = users.id
                            AND users_group_roles.group_role_id = (SELECT id FROM group_roles WHERE group_roles.group_id = ?)
                          WHERE groups_users.group_id = ?
                          ', group_id, group_id)

    return members
  end

  # Delete a user from a chat group
  #
  # @param [Integer] member_id The ID of the user to kick
  # @param [Integer] group_id The ID of the group
  #
  # @return [nil]
  def delete_member(member_id, group_id)
    db = connect_db()

    member = db.execute('SELECT * FROM groups_users WHERE user_id = ? AND group_id = ?', member_id, group_id).first

    if (!member)
      raise "No member with id #{member_id} was found"
    end

    user_id = member['user_id']

    group = get_group_by_id(group_id)

    # ska ej kunna ta bort skaparen av gruppen
    if (!group['creator'] != user_id.to_i)
      # delete user group role relation
      db.execute('DELETE FROM users_group_roles WHERE user_id = ? AND group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)', member_id, group_id)

      # delete user group relation
      db.execute('DELETE FROM groups_users WHERE user_id = ? AND group_id = ?', member_id, group_id)
    end

    return nil
  end

  # Returns whether or not a user can kick another user in a chat group
  #
  # @param [Integer] user_id The ID of the user that should have the permission to kick
  # @param [Integer] member_id The ID of the user to kick
  # @param [Integer] group_id The ID of the group
  #
  # @return [Boolean]
  def user_can_kick(user_id, member_id, group_id)
    if (group['creator'] == user_id)
      return true
    end

    db = connect_db()

    user = get_user_by_id(user_id)
    member = get_user_by_id(member_id)
    group = get_group_by_id(group_id)

    user_role_id = db.execute('SELECT * FROM users_group_roles WHERE user_id = ? AND group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)', user_id, group_id).first
    if (!user_role_id)
      return false
    end
    user_role_id = user_role_id['group_role_id']

    user_role = db.execute('SELECT * FROM group_roles WHERE id = ?', user_role_id).first

    return (user_role && user_role['canKick'] == 'on')
  end

  # Create a role in a chat group
  #
  # @param [Integer] group_id The ID of the group
  # @param [String] title The name of the role
  # @param [Boolean] can_delete True if the role should allow deletion of messages
  # @param [Boolean] can_kick True if the role should allow kicking of members
  #
  # @return [nil]
  def create_role(group_id, title, can_delete, can_kick)
    db = connect_db()

    db.execute('INSERT INTO group_roles (group_id, title, canDelete, canKick) VALUES (?, ?, ?, ?)', group_id, title, can_delete, can_kick)
    return nil
  end

  # Find a role by id
  #
  # @param [Integer] role_id The ID of the role to find
  #
  # @return [Hash]
  #   * :id [Integer] The ID of the role
  #   * :group_id [Integer] The ID of the group
  #   * :title [String] The name of the role
  #   * :canDelete [String] "on" if the user can delete messages
  #   * :canKick [String] "on" if the user can kick members
  def get_role(role_id)
    if (!role_id)
      return nil
    end

    db = connect_db()

    role = db.execute('SELECT * FROM group_roles WHERE id = ?', role_id).first
    return role
  end

  # Find all roles in a chat group
  #
  # @param [Integer] group_id The ID of the group
  #
  # @return [Array<Hash>]
  #   * :id [Integer] The ID of the role
  #   * :group_id [Integer] The ID of the group
  #   * :title [String] The name of the role
  #   * :canDelete [String] "on" if the user can delete messages
  #   * :canKick [String] "on" if the user can kick members
  def get_roles_in_group(group_id)
    db = connect_db()

    group_roles = db.execute('SELECT * FROM group_roles WHERE group_id = ?', group_id)

    return group_roles
  end

  # Update a role
  #
  # @param [Integer] role_id The ID of the role to update
  # @param [String] title The new name of the role
  # @param [Boolean] can_delete The new value of canDelete
  # @param [Boolean] can_kick The new value of canKick
  #
  # @return [nil]
  def update_role(role_id, title, can_delete, can_kick)
    db = connect_db()

    db.execute('UPDATE group_roles
                SET title = ?,
                    canDelete = ?,
                    canKick = ?
                WHERE id = ?', title, can_delete, can_kick, role_id)

    return nil
  end

  # Assign a group role to a member in a char group
  #
  # @param [Integer] group_id The ID of the group
  # @param [Integer] user_id The ID of the user
  # @param [Integer] role_id The ID of the role to assign to user
  #
  # @return [nil]
  def update_role_of_user_in_group(group_id, user_id, role_id)
    db = connect_db()

    current_role_id = db.execute('SELECT 
                                  users_group_roles.group_role_id
                                FROM 
                                  users_group_roles
                                LEFT JOIN users
                                  ON users.id = users_group_roles.user_id
                                INNER JOIN group_roles
                                  ON group_roles.id = users_group_roles.group_role_id
                                WHERE group_roles.group_id = ?
                                AND users.id = ?
                                ', group_id, user_id).first

    puts('CURRENT:', current_role_id)

    if (current_role_id)
      current_role_id = current_role_id['group_role_id']
      if !role_id

        # update role_id
        db.execute('UPDATE users_group_roles
                  SET group_role_id = ?
                  WHERE users_group_roles.group_role_id =
                    (SELECT id 
                      FROM group_roles 
                    WHERE group_id = ?)
                  AND user_id = ?', role_id, group_id, user_id)
      else
        # delete role from user
        db.execute('DELETE FROM users_group_roles
                    WHERE users_group_roles.group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)
                    AND user_id = ?', group_id, user_id)
      end
    else
      # create new relation
      db.execute('INSERT INTO users_group_roles (group_role_id, user_id) VALUES (?, ?)', role_id, user_id)
    end

    return nil
  end

  # Delete a group role
  #
  # @param [Integer] group_id The ID of the group
  # @param [Integer] role_id The ID of the role to delete
  #
  # @return [nil]
  def delete_role_in_group(group_id, role_id)
    db = connect_db()

    db.execute('DELETE FROM group_roles, users_group_roles
                FROM group_roles
                INNER JOIN users_group_roles ON group_roles.id = users_group_roles.group_role_id
                WHERE group_roles.id = ?
                AND group_roles.group_id', role_id, group_id)

    return nil
  end

  # Returns whether or not a user is the creator of a chat group
  #
  # @param [Integer] group_id The ID of the group
  # @param [Integer] user_id The ID of the user
  #
  # @return [Boolean]
  def user_is_owner_of_group(group_id, user_id)
    group = get_group_by_id(group_id)

    return group['creator'] == user_id
  end

  # Update a message
  #
  # @param [Integer] message_id The ID of the message
  # @param [String] new_message The new message
  #
  # @return [nil]
  def update_message(message_id, new_message)
    db = connect_db()

    db.execute('UPDATE messages SET message = ? WHERE id = ?', new_message, message_id)

    return nil
  end
end
