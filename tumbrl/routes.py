# Aqui vão as rotas e os links
from tumbrl import app
from flask import render_template, url_for, redirect
from flask_login import login_required, login_user, current_user, logout_user
from tumbrl.models import load_user
from tumbrl.forms import FormLogin, FormCreateNewAccount, FormCreateNewPost
from tumbrl import bcrypt
from tumbrl.models import User, Posts, Like
from tumbrl import database

import os
from werkzeug.utils import secure_filename

# A primeira página será a pagina de login caso ele não esteja logado ainda
@app.route('/login', methods=['POST', 'GET'])
@app.route('/', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home', user_id=current_user.id))

    _formLogin = FormLogin()
    if _formLogin.validate_on_submit():
        userToLogin = User.query.filter_by(email=_formLogin.email.data).first()
        if userToLogin and bcrypt.check_password_hash(userToLogin.password, _formLogin.password.data):
            # Verificando se está correto o login ou se ele já está logado
            login_user(userToLogin, remember=_formLogin.remember.data)
            return redirect(url_for('home', user_id=current_user.id))

    return render_template('login.html', form=_formLogin)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# Vai ser o feed com as postagens.
@app.route('/home')
@login_required
def home():
    _postagens = Posts.query.order_by(Posts.id.desc()).all()
    return render_template('home.html', postagens=_postagens)




@app.route('/new', methods=['POST', 'GET'])
def createAccount():
    _formCreateNewAccount = FormCreateNewAccount()

    if _formCreateNewAccount.validate_on_submit():
        password = _formCreateNewAccount.password.data
        password_cr = bcrypt.generate_password_hash(password)
        # print(password)
        # print(password_cr)

        newUser = User(
            username=_formCreateNewAccount.usarname.data,
            email=_formCreateNewAccount.email.data,
            password=password_cr
        )

        # Adicionando usuário na base de dados
        database.session.add(newUser)
        database.session.commit()

        # Realiza login do usuário e redireciona ele para a página de perfil.
        login_user(newUser, remember=True)
        return redirect(url_for('profile', user_id=newUser.id))

    # Se o form não for válido, irá renderizar o new.html mesmo.
    return render_template('new.html', form=_formCreateNewAccount)


@app.route('/perry')
def perry():
    return render_template('perry.html')


@app.route('/teste')
def teste():
    return render_template('teste.html')


@app.route('/profile/<user_id>', methods=['POST', 'GET'])
@login_required
def profile(user_id):
    if int(user_id) == int(current_user.id):
        _formCreateNewPost = FormCreateNewPost()

        if _formCreateNewPost.validate_on_submit():
            photo_file = _formCreateNewPost.photo.data
            photo_name = secure_filename(photo_file.filename)

            photo_path = f'{os.path.abspath(os.path.dirname(__file__))}/{app.config["UPLOAD_FOLDER"]}/{photo_name}'
            photo_file.save(photo_path)

            _postText = _formCreateNewPost.text.data

            newPost = Posts(post_text=_postText, post_img=photo_name, user_id=int(current_user.id))
            database.session.add(newPost)
            database.session.commit()

        return render_template('profile.html', user=current_user, form=_formCreateNewPost)

    else:
        _user = User.query.get(int(user_id))
        return render_template('profile.html', user=_user, form=None)



@app.route('/like_post/<post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Posts.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if existing_like:
        # Usuário já curtiu a postagem, não faça nada ou remova a curtida
        database.session.delete(existing_like)
        database.session.commit()
    else:
        # Adiciona uma nova curtida
        new_like = Like(user_id=current_user.id, post_id=post_id)
        database.session.add(new_like)
        database.session.commit()

    return redirect(url_for('home'))




@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Posts.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        # Redireciona se o usuário atual não for o dono da postagem
        return redirect(url_for('home'))

    database.session.delete(post)
    database.session.commit()
    return redirect(url_for('profile', user_id=current_user.id))
