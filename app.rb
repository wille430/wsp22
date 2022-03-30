require "sinatra"
require "sqlite3"
require "slim"
require "bcrypt"
require "sinatra/reloader"
require "./model.rb"

enable :sessions

public_routes = [
  "/login",
  "/signup",
]

before do
  # redirect to login if user is trying to access route that requires user authentication
  if !(public_routes.include? request.path_info) && !session[:user_id]
    redirect("/login")
  elsif request.path_info.match(/\/groups\/+?\d+/)

    # check if user is a member of the group if route is /groups/:group_id
    group_id = params[:group_id]
    user_id = session[:user_id]

    db = connect_db()

    # check if user is a member of group
    group_user = db.execute("SELECT
              1
              FROM groups_users
              WHERE user_id = ?
              AND group_id = ?", user_id, group_id)

    if (!group_user)
      # show error message: unauthorized
      return "You are not a member of this group"
    end
  end

  # TODO: check if creator for certain routes
end

# START HELPERS

helpers do
  def groups(user_id = session[:user_id])
    return get_groups_of_user(user_id)
  end

  def members(group_id = params[:group_id])
    return get_members_in_group(group_id)
  end

  def role(role_id = params[:role_id])
    return get_role(role_id)
  end

  def group(group_id = params[:group_id])
    return get_group_by_id(group_id)
  end
end

# END HELPERS

# START ROUTES

# AUTH

get("/login") do
  slim(:login)
end

post("/login") do
  username = params[:username]
  password = params[:password]

  begin
    login_user(username, password)
  rescue => exception
    return exception.message
  else
    redirect("/")
  end
end

get("/signup") do
  slim(:signup)
end

# USERS

post("/users/new") do
  username = params[:username]
  password = params[:password]
  confirm_password = params[:confirm_password]

  begin
    register_user(username, password, confirm_password)
  rescue => exception
    return exception.message
  else
    redirect("/")
  end
end

# GROUPS

get("/") do
  slim(:"groups/index")
end

# TODO: bestäm vad om /groups eller / ska användas för grupp index
get("/groups") do
  redirect("/")
end

post("/groups") do
  group_name = params[:name]
  user_id = session[:user_id]

  create_group(user_id, group_name)

  redirect("/")
end

get("/groups/new") do
  slim(:"groups/new")
end

get("/groups/:group_id") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_exists_in_group(group_id, user_id))
    return "You are not a member of this group"
  end

  group = get_group_by_id(group_id)
  messages = get_messages_in_group(group_id)

  slim(:"groups/show", locals: { group: group, messages: messages })
end

get("/groups/:group_id/edit") do
  slim(:"groups/edit")
end

post("/groups/:group_id/update") do
  group_id = params[:group_id]
  user_id = session[:user_id]
  title = params[:title]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  update_group(group_id, title)

  redirect("/groups/#{group_id}")
end

post("/groups/:group_id/destroy") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  delete_group(group_id)

  redirect("/groups")
end

# MESSAGES

post("/groups/:group_id/messages") do
  group_id = params[:group_id]
  message = params[:message]
  user_id = session[:user_id]

  if (!user_exists_in_group(group_id, user_id))
    return "You are not a member of this group"
  end

  create_message_in_group(group_id, user_id, message)

  redirect("/groups/#{group_id}")
end

post("/groups/{group_id}/messages/{message_id}/update") do
  group_id = params[:group_id]
  message_id = params[:message_id]
  user_id = session[:user_id]

  begin
    delete_message(group_id, message_id, user_id)
  rescue => e
    return e.message
  end
end

post("/groups/{group_id}/messages/:message_id/destroy") do
  group_id = params[:group_id]
  message_id = params[:message_id]
  user_id = session[:user_id]

  begin
    delete_message(group_id, message_id, user_id)
  rescue => e
    return e.message
  end

  redirect("/groups/#{group_id}")
end

# MEMBERS

post("/groups/:group_id/members") do
  new_member_username = params[:new_member_username]
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  begin
    add_member_to_group(group_id, new_member_username)
  rescue => e
    return e.message
  end

  redirect("/groups/#{group_id}/members/edit")
end

get("/groups/:group_id/members/edit") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  # check if user is owner of group
  group_roles = get_roles_in_group(group_id)

  slim(:"members/edit", locals: { group_roles: group_roles })
end

# TODO: DELETE MEMBER
post("/groups/{group_id}/members/{member_id}/destroy") do
  group_id = params[:group_id]
  member_id = params[:member_id]
  user_id = session[:user_id]

  if (!user_can_kick(user_id, member_id, group_id))
    return "You dont have permission to kick member with id #{member_id}"
  end

  delete_member(member_id, group_id)

  redirect("groups/#{group_id}/members/edit")
end

# ROLES

get("/groups/:group_id/roles") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  roles = get_roles_in_group(group_id)

  slim(:"roles/index", locals: { roles: roles })
end

get("/groups/:group_id/roles/new") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  slim(:"roles/new")
end

post("/groups/:group_id/roles") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  create_role(group_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

get("/groups/:group_id/roles/:role_id") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  slim(:"roles/show")
end

get("/groups/:group_id/roles/:role_id/edit") do
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  slim(:"roles/edit")
end

post("/groups/:group_id/roles/:role_id/update") do
  group_id = params[:group_id]
  user_id = session[:user_id]
  role_id = params[:role_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  title = params[:title]
  can_delete = params[:can_delete]
  can_kick = params[:can_kick]

  update_role(role_id, title, can_delete, can_kick)

  redirect("/groups/#{group_id}/roles")
end

post("/groups/:group_id/roles/:role_id/destroy") do
  # TODO: delete role and remove role from all users with the role
  role_id = params[:role_id]
  group_id = params[:group_id]
  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  delete_role_in_group(group_id, role_id)

  redirect("/groups/#{group_id}/roles")
end

# MEMBER ROLES RELATION

post("/groups/:group_id/members/:user_id/role/update") do
  role_id = params[:role_id]
  group_id = params[:group_id]
  member_user_id = params[:user_id]

  user_id = session[:user_id]

  if (!user_is_owner_of_group(group_id, user_id))
    return "You are not the owner of this group"
  end

  update_role_of_user_in_group(group_id, member_user_id, role_id)

  redirect("/groups/#{group_id}/members/edit")
end
