from flask import Flask, render_template, request, redirect, jsonify
from flask import url_for, flash

from sqlalchemy import create_engine, desc, asc
from sqlalchemy.orm import sessionmaker
from catalog_db_setup import Base, Catalog, Item, User

from flask import session as login_session
# this login_session object works like a dictionary. We can store
# values in it for the longevity of a user's session with our server
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# CLIENT_SECRET = 'client_secrets.json'
CLIENT_ID = json.loads(
  open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogwithuser.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# show all catalog and newly added items
@app.route('/')
@app.route('/main/')
def mainPage():
    catalogs = session.query(Catalog).order_by(asc(Catalog.name))
    items = session.query(Item).order_by(desc(Item.time_created))

    return render_template('index.html', catalogs=catalogs, items=items)


# add new item where a list of existing catalog can be selected from
@app.route('/newitem/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    catalogs = session.query(Catalog).all()

    if request.method == 'POST':
        user_id = login_session['user_id']
        name = request.form['name']
        description = request.form['description']
        catalog = request.form['catalog']
        catalog_query = session.query(Catalog).filter_by(name=catalog).one()
        catalog_id = catalog_query.id

        if name and description:
            newItem = Item(
                name=name, user_id=user_id,
                description=description, catalog_id=catalog_id)
            session.add(newItem)
            flash('New Item [ %s ] Successfully Created' % newItem.name)
            session.commit()
            return redirect(url_for('mainPage'))
        else:
            error = 'name and description of item, please!'
            return render_template(
                    'newitem.html', error=error, catalogs=catalogs)
    else:
        return render_template(
            'newitem.html', catalogs=catalogs)


# add new catalog
@app.route('/catalog/new', methods=['GET', 'POST'])
def newCatalog():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        name = request.form['name']
        user_id = login_session['user_id']
        if name:
            newCatalog = Catalog(
                name=name, user_id=user_id)
            session.add(newCatalog)
            flash('New Catalog [ %s ] Successfully Creaded' % newCatalog.name)
            session.commit()
            return redirect(url_for('mainPage'))
        else:
            error = "name of catalog, please!"
            return render_template(
                'newcatalog.html', error=error)
    else:
        return render_template(
                'newcatalog.html')


# show one catalog and all items under it
@app.route('/catalog/<int:catalog_id>/', methods=['GET'])
def showCatalog(catalog_id):
    catalog = session.query(
        Catalog).filter_by(id=catalog_id).one()
    items = session.query(
        Item).filter_by(catalog_id=catalog_id).order_by(asc(Item.name))
    return render_template(
                'catalog.html', catalog=catalog, items=items)


# show detail info of one item
@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/', methods=['GET'])
def showItem(catalog_id, item_id):
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template(
                'item.html', item=item, catalog=catalog)


# add new item in selected catalog
@app.route(
    '/catalog/<int:catalog_id>/newitem', methods=['GET', 'POST'])
def addItem(catalog_id):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    catalog = session.query(
        Catalog).filter_by(id=catalog_id).one()

    if request.method == 'POST':
        user_id = login_session['user_id']
        name = request.form['name']
        description = request.form['description']

        if name and description:
            newItem = Item(
                name=name, user_id=user_id,
                description=description, catalog_id=catalog_id)
            session.add(newItem)
            flash('New Item [ %s ] Successfully Created' % newItem.name)
            session.commit()
            return redirect(url_for('showCatalog', catalog_id=catalog_id))
        else:
            error = 'name and description of item, please!'
            return render_template(
                    'additem.html', error=error, catalog=catalog)
    else:
        return render_template(
            'additem.html', catalog=catalog)


# edit name of catalog
@app.route('/catalog/<int:catalog_id>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_id):
    editCatalog = session.query(
        Catalog).filter_by(id=catalog_id).one()

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    if editCatalog.user_id != login_session['user_id']:
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        if request.form['name']:
            editCatalog.name = request.form['name']
            session.add(editCatalog)
            session.commit()
            flash('Catalog has been renamed!')
            return redirect(url_for('showCatalog', catalog_id=catalog_id))
        else:
            error = "Enter new name, please!"
            return render_template(
                'editcatalog.html', editCatalog=editCatalog, error=error)
    else:
        return render_template(
                    'editcatalog.html', editCatalog=editCatalog)


# delete selected catalog
@app.route('/catalog/<int:catalog_id>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalog_id):
    deleteCatalog = session.query(
        Catalog).filter_by(id=catalog_id).one()
    deleteItems = session.query(
        Item).filter_by(catalog_id=catalog_id).all()

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    if deleteCatalog.user_id != login_session['user_id']:
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        session.delete(deleteCatalog)
        flash('Catalog [ %s ] has been deleted!' % deleteCatalog.name)
        session.commit()
        for item in deleteItems:
            session.delete(item)
            session.commit()
        return redirect(url_for('mainPage'))

    else:
        return render_template(
            'deletecatalog.html', deleteCatalog=deleteCatalog)


# edit selected item. can update catalog, name and description
@app.route(
    '/catalog/<int:catalog_id>/item/<int:item_id>/edit/',
    methods=['GET', 'POST'])
def editItem(catalog_id, item_id):
    catalogs = session.query(
        Catalog).all()
    editItem = session.query(
        Item).filter_by(catalog_id=catalog_id).one()

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    if editItem.user_id != login_session['user_id']:
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        catalog = request.form['catalog']
        name = request.form['name']
        description = request.form['description']
        if name and description:
            editItem.catalog_id = catalog
            editItem.name = name
            editItem.description = description
            flash('Item [ %s ] has been updated!' % editItem.name)
            session.add(editItem)
            session.commit()
            return redirect(url_for(
                'showItem', catalog_id=editItem.catalog_id, item_id=item_id))
        else:
            error = "Enter new name and description of the item, please!"
            return render_template(
                'edititem.html', catalogs=catalogs, item=editItem, error=error)
    else:
        return render_template(
            'edititem.html', catalogs=catalogs, item=editItem)


@app.route(
    '/catalog/<int:catalog_id>/item/<int:item_id>/delete/',
    methods=['GET', 'POST'])
def deleteItem(catalog_id, item_id):
    deleteItem = session.query(
        Item).filter_by(id=item_id).one()

    if 'username' not in login_session:
        return redirect(url_for('showLogin'))

    if deleteItem.user_id != login_session['user_id']:
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        session.delete(deleteItem)
        flash('Item [ %s ] has been deleted!' % deleteItem.name)
        session.commit()
        return redirect(url_for('mainPage'))
    else:
        return render_template(
            'deleteitem.html', deleteItem=deleteItem)


# Create a state token to prevent request forgery
# Store it in the session for later validation
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# User helper function. create user, get user info, and get user id
def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfro(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Facebook sign in
@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data

    # Exchange client token for long-lived server-side token
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = (
        'https://graph.facebook.com/oauth/access_token?'
        'grant_type=fb_exchange_token&client_id=%s&'
        'client_secret=%s&fb_exchange_token=%s'
        ) % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # strip expire tag from access token
    token = result.split('&')[0]
    # use token to get user inforamtion from API
    url = 'https://graph.facebook.com/v2.7/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token much be stored in the login_session in order to properly logout
    stored_token = token.split('=')[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.7/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data['data']['url']
    print data
    print login_session['picture']
    # check if user exists
    user_id = getUserID(login_session['email'])
    print user_id
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px; -webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"'
    flash('you are now logged in as %s' % login_session['username'])

    return output


# Facebook log out
# revoke a current user's token and reset their login_session
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session.get('facebook_id')
    # the access_token must be included to successfully logout
    access_token = login_session.get('access_token')
    url = (
        'https://graph.facebook.com/%s/permissions?access_token=%s' %
        (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    print result
    return 'you have been logged out'


# Google sign in
@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    auth_code = request.data

    try:
        # upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(auth_code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check that the access token is valid
    access_token = str(credentials.access_token)
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token)
    h = httplib2.Http()
    token_result = json.loads(h.request(url, 'GET')[1])

    if token_result.get('error') is not None:
        response = make_response(
            json.dumps(token_result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is used for the intended user
    google_id = credentials.id_token['sub']

    if token_result['user_id'] != google_id:
        response = make_response(
            json.dumps('Token\'s user ID doesn\'t match given user id'),
            500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is valid for this app
    if token_result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps('Token\'s client ID doesn\'t match app\'s'),
            500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_google_id = login_session.get('gplus_id')

    if stored_access_token is not None and google_id == stored_google_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = google_id

    # get user Information
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # add provider to login session
    login_session['provider'] = 'google'

    # check if user exists
    user_id = str(getUserID(data['email']))

    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px; -webkit-border-radius: 150px;'
    output += '-moz-border-radius: 150px;"'

    flash('you are now logged in as %s' % login_session['username'])
    print 'done. sign in google account'
    return output


# google disconnect.
# revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % (
        login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        response = make_response(
            json.dumps('Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    print login_session
    if 'provider' in login_session:
        print login_session['provider']
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']

        flash('You have been successfully logged out.')
        return redirect(url_for('mainPage'))

    else:

        flash('You were not logged in to begin with!')
        return redirect(url_for('mainPage'))


# Making an API endpoint (GET request) of Item
@app.route('/catalog/<int:catalog_id>/item/JSON')
def catalogItemJSON(catalog_id):
    items = session.query(Item).filter_by(
        catalog_id=catalog_id).all()

    return jsonify(CatalogItems=[item.serialize for item in items])


# Making an API endpoint (GET request) of Catalog
@app.route('/catalogs/JSON')
def catalogJSON():
    catalogs = session.query(Catalog).all()

    return jsonify(Catalogs=[catalog.serialize for catalog in catalogs])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
