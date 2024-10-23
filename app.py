from flask import Flask
from flask_wtf import FlaskForm
from flask import render_template, request, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user,logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError, StringField, PasswordField, SubmitField, SelectField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import pytz
import os
import boto3
from werkzeug.utils import secure_filename
import uuid
from flask_migrate import Migrate
from datetime import datetime, date
import io
from PIL import Image
from dateutil.relativedelta import relativedelta

from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

# S3クライアントの設定
s3 = boto3.client('s3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION")
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SECRET_KEY"] = os.urandom(24)
app.config['S3_BUCKET'] = os.getenv("S3_BUCKET")
app.config['S3_LOCATION'] = f"https://{app.config['S3_BUCKET']}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/"
db = SQLAlchemy(app)
# Flask-Migrateの設定
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

def tokyo_time():
    return datetime.now(pytz.timezone('Asia/Tokyo'))

class RegistrationForm(FlaskForm):
    display_name = StringField('表示ネーム', validators=[DataRequired(), Length(min=3, max=30)])
    user_name = StringField('ユーザー名', validators=[DataRequired()])
    furigana = StringField('フリガナ', validators=[DataRequired()])
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])
    email_confirm = StringField('メールアドレス確認', validators=[DataRequired(), Email(), EqualTo('email', message='メールアドレスが一致していません')])
    password = PasswordField('パスワード', validators=[DataRequired(), Length(min=8, message='Password must be at least 8 characters long'), EqualTo('pass_confirm', message='パスワードが一致していません')])
    pass_confirm = PasswordField('パスワード(確認)', validators=[DataRequired()])
    gender = SelectField('性別', choices=[('male', '男性'), ('female', '女性'), ('other', 'その他'), ('prefer_not_to_say', '答えたくない')], validators=[DataRequired()])
    date_of_birth = DateField('生年月日', format='%Y%m%d', validators=[DataRequired()])
    submit = SubmitField('登録')

    def validate_display_name(self, field):
        if User.query.filter_by(display_name=field.data).first():
            raise ValidationError('入力された表示ネームは既に使われています。')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('入力されたメールアドレスは既に登録されています。')
        
class BlogCategoryForm(FlaskForm):
    category = StringField('カテゴリ名', validators=[DataRequired()])
    submit = SubmitField('保存')

    def validate_category(self, field):
        if BlogCategory.query.filter_by(category=field.data).first():
            raise ValidationError('入力されたカテゴリ名は既に使われています。')


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(300), nullable=False)    
    image_url = db.Column(db.String(255), nullable=True) 
    created_at = db.Column(db.DateTime, nullable=False, default=tokyo_time)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # サインアップフィールド
    display_name = db.Column(db.String(30), unique=True, nullable=False)  # 表示ネーム
    user_name = db.Column(db.String(100), nullable=False)  # 名前
    furigana = db.Column(db.String(100), nullable=False)  # フリガナ
    email = db.Column(db.String(120), unique=True, nullable=False)  # メールアドレス
    password = db.Column(db.String(128), nullable=False)  # パスワード
    gender = db.Column(db.String(20), nullable=True)  # 性別
    date_of_birth = db.Column(db.Date, nullable=False)  # 生年月日
    administrator = db.Column(db.Boolean, nullable=False, default=False)
    
    def __init__(self, display_name, user_name, furigana, email, password, gender, date_of_birth, administrator="0"):
        self.display_name = display_name
        self.user_name = user_name
        self.furigana = furigana
        self.email = email
        self.password = password  
        self.gender = gender
        self.date_of_birth = date_of_birth
        self.administrator = administrator
                            

    def __repr__(self):
        return f'<User {self.display_name}>'

    # def age(self):
    #     today = date.today()
    #     return today.year - self.date_of_birth.year - ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))

    def age(self):
        today = date.today()
        return relativedelta(today, self.date_of_birth).years
    
class BlogCategory(db.Model):
    __tablename__ = 'blog_category'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(140))
    posts = db.relationship('BlogPost', backref='blogcategory', lazy='dynamic')

    def __init__(self, category):
        self.category = category
    
    def __repr__(self):
        return f"CategoryID: {self.id}, CategoryName: {self.category} \n"

    def count_posts(self, id):
        return BlogPost.query.filter_by(category_id=id).count()
    
class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('blog_category.id'))
    date = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Tokyo')))
    title = db.Column(db.String(140))
    text = db.Column(db.Text)
    summary = db.Column(db.String(140))
    featured_image = db.Column(db.String(140))

    def __init__(self, title, text, featured_image, user_id, category_id, summary):
        self.title = title
        self.text = text
        self.featured_image = featured_image
        self.user_id = user_id
        self.category_id = category_id
        self.summary = summary

    def __repr__(self):
        return f"PostID: {self.id}, Title: {self.title}, Author: {self.author} \n"
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route("/")
# @login_required
def index():    
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("index.html", posts=posts)
    

@app.route('/signup', methods=['GET','POST'])
def signup():    
    form = RegistrationForm()    

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(
            email=form.email.data,
            user_name=form.user_name.data,
            display_name=form.display_name.data,
            furigana=form.furigana.data,
            password=hashed_password,  # ハッシュ化されたパスワードを使用
            gender=form.gender.data,
            date_of_birth=form.date_of_birth.data,
            administrator="0"  # もしadministratorフィールドが必要であれば
        )
        db.session.add(user)
        db.session.commit()
        flash('ユーザーが登録されました')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect("/")
        else:
            flash("Invalid email or password")
    return render_template("login.html", form=form)

        
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        image = request.files.get("image")
        category_id = request.form['category_id']

        
        if image and image.filename != '': 
            original_filename = secure_filename(image.filename)
            # ファイル名にユニークなIDを追加して変更
            unique_filename = f"{uuid.uuid4().hex}_{original_filename}"


            # 画像を読み込む
            img = Image.open(image)
            max_width = 1500  # 最大横幅を1500pxに設定

            # 画像の横幅が1500pxを超えている場合に縮小
            if img.width > max_width:
                # アスペクト比を維持したままリサイズ
                new_height = int((max_width / img.width) * img.height)                
                img = img.resize((max_width, new_height), Image.LANCZOS)

            # リサイズされた画像をバイトIOオブジェクトに保存
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG')
            img_byte_arr.seek(0)

             # リサイズされた画像をS3にアップロード
            s3.upload_fileobj(
                img_byte_arr,
                app.config['S3_BUCKET'],
                unique_filename
            )
            image_url = f"{app.config['S3_LOCATION']}{unique_filename}"
        else:
            image_url = None

        new_post = Post(title=title, body=body, image_url=image_url, category_id=category_id)
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    return render_template("create.html", categories=categories)
    
@app.route("/<int:id>/update", methods=["GET", "POST"])
@login_required
def update(id):
    post = Post.query.get(id)
    if request.method == "GET":
        return render_template("update.html", post=post)
    
    else:
        post.title = request.form.get("title")
        post.body = request.form.get("body")
        post.category_id = request.form.get("category_id")
        db.session.commit()
        return redirect("/")
    

@app.route('/category_maintenance', methods=['GET', 'POST'])
@login_required
def category_maintenance():
    page = request.args.get('page', 1, type=int)
    blog_categories = BlogCategory.query.order_by(BlogCategory.id.asc()).paginate(page=page, per_page=10)
    form = BlogCategoryForm()
    if form.validate_on_submit():
        blog_category = BlogCategory(category=form.category.data)
        db.session.add(blog_category)
        db.session.commit()
        flash('ブログカテゴリが追加されました')
        return redirect(url_for('category_maintenance'))
    elif form.errors:
        form.category.data = ""
        flash(form.errors['category'][0])
    return render_template('category_maintenance.html', blog_categories=blog_categories, form=form)
                            

@app.route("/<int:id>/delete")
@login_required
def delete(id):
    post = Post.query.get(id)
    db.session.delete(post)
    db.session.commit()
    return redirect("/")  


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)