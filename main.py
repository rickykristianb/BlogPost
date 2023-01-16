from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterUserForm, CreatePostForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy.exc import IntegrityError
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)

print(os.environ['SECRET_KEY'])

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


login_manager.login_view = "login"
login_manager.login_message = u"You need to login to access the page"


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # relationship one to many with children user (User is parent)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="blogpost")
    # ----------------------
    # Relationship one to many with children is Comment(BlogPost is parent) 1 blogpost can have many comments
    comment = relationship("Comment", back_populates="blogpost")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    # Relationship one to many with children blogpost (User is parent)
    blogpost = relationship("BlogPost", back_populates="author")
    # ----------------------
    # Relationship one to many with children Comment (User is parent) 1 user can have many comments
    comment = relationship("Comment", back_populates="user")
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(150), nullable=False)


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(250), nullable=False)
    # Relationship one to many with children is comment (User is parent)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = relationship("User", back_populates="comment")
    # Relationship one to many with children is Comment(BlogPost is parent) 1 blog post can have many comments
    blogpost_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blogpost = relationship("BlogPost", back_populates="comment")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        print(request.form.get("email"))
        new_user = User(
            email=form.email.data,
            password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8),
            name=form.name.data,
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            user = load_user(new_user.id)
            login_user(user)
            return redirect(url_for("get_all_posts"))
        except IntegrityError:
            flash("You already registered. Login instead")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        get_user = User.query.filter_by(email=email).first()
        try:
            is_password_correct = check_password_hash(pwhash=get_user.password, password=form.password.data)
            if is_password_correct:
                user = load_user(get_user.get_id())
                login_user(user)
                return redirect(url_for("get_all_posts"))
            flash("Your password is wrong")
            return render_template("login.html", form=form)
        # except UndefinedError:
        #     form = RegisterUserForm()
        #     flash("There is no user in the database, please register as admin first")
        #     return render_template("register.html", form=form)
        except Exception:
            db.session.rollback()
            form = RegisterUserForm()
            flash("There is no user in the database, please register as admin first")
            return redirect(url_for("register"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    gravatar = Gravatar(app,
                        size=100,
                        )
    comment_post_id = str(post_id)
    requested_post = BlogPost.query.get(post_id)
    comments = db.session.query(Comment).filter(Comment.blogpost_id == comment_post_id)
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            comment=form.comment.data,
            user_id=current_user.get_id(),
            blogpost_id=post_id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=form, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.get_id() == "1":
            return function(*args, **kwargs)
        return u"Access Denied, you need admin to add post", 403
    return wrapper


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
    # with app.app_context():
    #     db.create_all()