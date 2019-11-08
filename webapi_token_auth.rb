# webapi_token_auth.rb
require 'sinatra'
require 'json'

# This is our database of users
users = { 'thibault@samurails.com' => 'supersecret' }

# We will store tokens in this hash
tokens = {}

helpers do
  def unauthorized!
    response.headers['WWW-Authenticate'] = 'Token realm="Token Realm"'
    halt 401
  end

  def authenticate!(tokens)
    auth = env['HTTP_AUTHORIZATION']
    # We check if the Authorization header was provided
    # and if it matches the format we want: Token lfkdsfkdsjfsf
    unauthorized! unless auth && auth.match(/Token .+/)
    _, access_token = auth.split(' ')
    # Then we check in the tokens hash if there
    # is a token with the value sent by the client
    unauthorized! unless tokens[access_token]
  end
end

get '/' do
  authenticate!(tokens)
  'Master Ruby Web APIs - Chapter 9'
end

post '/login' do
  params = JSON.parse(request.body.read)
  email = params['email']
  password = params['password']

  content_type 'application/json'
  # If the email and password are correct
  if users[email] && users[email] == params['password']
    # We generate a token
    token = SecureRandom.hex
    # Store it in the tokens hash with a way
    # to get the user from that token
    tokens[token] = email
    { 'access_token' => token }.to_json
  else
    # If not, we send back a generic error message
    # To prevent attackers from knowing when they got
    # an email or password correctly.
    halt 400, { error: 'Invalid username or password.' }.to_json
  end
end

delete '/logout' do
  authenticate!(tokens)
  tokens.delete(access_token)
  halt 204
end