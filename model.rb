require "sinatra/reloader"

def connect_db(path = "db/database.db")
  db = SQLite3::Database.new(path)
  db.results_as_hash = true

  return db
end

def get_user_by_id(user_id)
  db = connect_db()

  return db.execute("SELECT * FROM users WHERE id = ?", user_id).first
end

def get_user_by_username(username)
  db = connect_db()

  return db.execute("SELECT * FROM users WHERE username = ?", username).first
end

def login_user(username, password)
  db = connect_db()

  # get user with username
  user = db.execute("SELECT * FROM users WHERE username = ?", username).first

  if user
    # compare password
    pwd_digest = user["pwd_digest"]

    if BCrypt::Password.new(pwd_digest) == password
      # login user
      session[:user_id] = user["id"]
    else
      raise "Invalid password or username"
    end
  else
    raise "Invalid username"
  end
end

def register_user(username, password, confirm_password)
  # validate password
  if !(password == confirm_password)
    # show error message: passwords not matching
    raise "Passwords not matching"
  end

  db = connect_db()

  # check for existing users
  user = db.execute("SELECT * FROM users WHERE username = ?", username).first
  if user
    # show error message: user exists already
    raise "Username is already in use"
  end

  # one-way encrypt password
  pwd_digest = BCrypt::Password.create(password)

  # create new user
  db.execute("INSERT INTO users (username, pwd_digest) VALUES (?, ?)", username, pwd_digest)

  # get id of new user
  user_id = db.execute("SELECT id FROM users WHERE username = ?", username)

  # save user_id in session
  session[:user_id] = user_id
end

def create_group(user_id, group_name)
  db = connect_db()

  # create group
  db.execute("INSERT INTO chat_groups (name, creator) VALUES (?, ?)", group_name, user_id)
  group_id = db.last_insert_row_id

  # add users to the group
  db.execute("INSERT INTO groups_users (user_id, group_id) VALUES (?, ?)", user_id, group_id)
end

def get_group_by_id(group_id)
  db = connect_db()
  group = db.execute("SELECT * FROM chat_groups WHERE id = ?", group_id).first
  return group
end

def update_group(group_id, name)
  db = connect_db()

  db.execute("UPDATE
                chat_groups
              SET name = ?
              WHERE id = ?", name, group_id)
end

def delete_group(group_id)
  db = connect_db()

  db.execute("DELETE FROM chat_groups WHERE id = ?", group_id)
end

def create_message_in_group(group_id, user_id, message)
  db = connect_db()

  # create message
  db.execute("INSERT INTO messages (message, group_id, user_id) VALUES (?, ?, ?)", message, group_id, user_id)
end

def get_messages_in_group(group_id)
  db = connect_db()

  # get messages from group with sender username
  messages = db.execute("SELECT 
                          messages.id,
                          users.username,
                          messages.message,
                          messages.user_id
                        FROM messages
                        LEFT JOIN users
                        ON messages.user_id = users.id
                        WHERE group_id = ?
                        ", group_id)
  return messages
end

def get_message_by_id(id)
  db = connect_db()

  message = db.execute("SELECT
                          *
                        FROM messages
                        LEFT JOIN users
                        ON users.id = messages.user_id
                        WHERE messages.id = ?", id).first

  return message
end

def update_message_in_group(group_id)
  # TODO
end

def delete_message(group_id, message_id, user_id)
  db = connect_db()

  message = get_message_by_id(message_id)
  group = get_group_by_id(group_id)

  # user is not group owner or creator of the message
  if (message["user_id"] != user_id && group["creator"] != user_id)
    raise "You don't have permissions to delete message with id #{message_id}"
  end

  db.execute("DELETE FROM messages WHERE id = ?", message_id)
end

def get_groups_of_user(user_id)
  db = connect_db()
  user_id = session[:user_id]

  if (!user_id)
    # return empty if not logged in
    return []
  end

  # get groups where user is a member of
  groups = db.execute("SELECT 
                        *,
                        chat_groups.id as id
                      FROM
                        chat_groups
                      INNER JOIN groups_users
                      ON (chat_groups.id = groups_users.group_id)
                      WHERE groups_users.user_id = ?
                      ", user_id)

  return groups
end

def username_exists(username)
  db = connect_db()

  # get the user id of user with username
  user = db.execute("SELECT id FROM users WHERE username = ?", username).first

  return user ? true : false
end

def user_exists_in_group(group_id, user_id)
  db = connect_db()

  is_member = db.execute("SELECT
              *
              FROM groups_users
              WHERE user_id = ?
              AND group_id = ?", user_id, group_id).first

  return is_member ? true : false
end

def add_member_to_group(group_id, new_member_username)
  db = connect_db()

  # get the user id of user with username
  if (!username_exists(new_member_username))
    # display error message
    raise "No user found with username #{new_member_username}"
  end

  user = get_user_by_username(new_member_username)
  user_id = user["id"]

  if (user_exists_in_group(group_id, user_id))
    # display error message
    raise "User is already a member of the group"
  end

  puts "Adding user #{user_id} to group #{group_id}"
  db.execute("INSERT INTO groups_users (user_id, group_id) VALUES (?, ?)", user_id, group_id)
end

def get_members_in_group(group_id)
  if (!group_id)
    return []
  end

  db = connect_db()

  members = db.execute("SELECT
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
                        ", group_id, group_id)

  return members
end

def delete_member(member_id, group_id)
  db = connect_db()

  member = db.execute("SELECT * FROM groups_users WHERE user_id = ? AND group_id = ?", member_id, group_id).first

  if (!member)
    raise "No member with id #{member_id} was found"
  end

  user_id = member["user_id"]

  group = get_group_by_id(group_id)

  # ska ej kunna ta bort skaparen av gruppen
  if (!group["creator"] != user_id.to_i)
    print("Deleting user #{member_id} from group #{group_id}")
    # delete user group role relation
    db.execute("DELETE FROM users_group_roles WHERE user_id = ? AND group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)", member_id, group_id)

    # delete user group relation
    db.execute("DELETE FROM groups_users WHERE user_id = ? AND group_id = ?", member_id, group_id)
  end
end

def user_can_kick(user_id, member_id, group_id)
  if (group["creator"] == user_id)
    return true
  end

  db = connect_db()

  user = get_user_by_id(user_id)
  member = get_user_by_id(member_id)
  group = get_group_by_id(group_id)

  user_role_id = db.execute("SELECT * FROM users_group_roles WHERE user_id = ? AND group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)", user_id, group_id).first
  if (!user_role_id)
    return false
  end
  user_role_id = user_role_id["group_role_id"]

  user_role = db.execute("SELECT * FROM group_roles WHERE id = ?", user_role_id).first

  return (user_role && user_role["canKick"] == "on")
end

def create_role(group_id, title, can_delete, can_kick)
  db = connect_db()

  db.execute("INSERT INTO group_roles (group_id, title, canDelete, canKick) VALUES (?, ?, ?, ?)", group_id, title, can_delete, can_kick)
end

def get_role(role_id)
  if (!role_id)
    return nil
  end

  db = connect_db()

  role = db.execute("SELECT * FROM group_roles WHERE id = ?", role_id).first
  return role
end

def get_roles_in_group(group_id)
  db = connect_db()

  group_roles = db.execute("SELECT * FROM group_roles WHERE group_id = ?", group_id)

  return group_roles
end

def update_role(role_id, title, can_delete, can_kick)
  db = connect_db()

  db.execute("UPDATE group_roles
              SET title = ?,
                  canDelete = ?,
                  canKick = ?
              WHERE id = ?", title, can_delete, can_kick, role_id)
end

def update_role_of_user_in_group(group_id, user_id, role_id)
  db = connect_db()

  current_role_id = db.execute("SELECT 
                                users_group_roles.group_role_id
                              FROM 
                                users_group_roles
                              LEFT JOIN users
                                ON users.id = users_group_roles.user_id
                              INNER JOIN group_roles
                                ON group_roles.id = users_group_roles.group_role_id
                              WHERE group_roles.group_id = ?
                              AND users.id = ?
                              ", group_id, user_id).first

  if (current_role_id)
    if !role_id
      # update role_id
      db.execute("UPDATE users_group_roles
                SET group_role_id = ?
                WHERE users_group_roles.group_role_id =
                  (SELECT id 
                    FROM group_roles 
                  WHERE group_id = ?)
                AND user_id = ?", role_id, group_id, user_id)
    else
      # delete role from user
      db.execute("DELETE FROM users_group_roles
                  WHERE users_group_roles.group_role_id = (SELECT id FROM group_roles WHERE group_id = ?)
                  AND user_id = ?", group_id, user_id)
    end
  else
    # create new relation
    db.execute("INSERT INTO users_group_roles (group_role_id, user_id) VALUES (?, ?)", role_id, user_id)
  end
end

def delete_role_in_group(group_id, role_id)
  db = connect_db()

  db.execute("DELETE FROM group_roles, users_group_roles
              FROM group_roles
              INNER JOIN users_group_roles ON group_roles.id = users_group_roles.group_role_id
              WHERE group_roles.id = ?
              AND group_roles.group_id", role_id, group_id)
end

def user_is_owner_of_group(group_id, user_id)
  group = get_group_by_id(group_id)

  return group["creator"] == user_id
end
