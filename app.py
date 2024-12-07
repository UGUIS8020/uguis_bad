from flask import Flask
from flask_wtf import FlaskForm
from flask import render_template, request, redirect, url_for, flash, abort, session
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError, StringField,  TextAreaField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_wtf.file import FileField, FileAllowed
import pytz
import os
import boto3
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime, date
import io
from PIL import Image, ExifTags
from dateutil.relativedelta import relativedelta
from botocore.exceptions import ClientError
from init_db import init_tables  # init_counter_tableから変更
import logging
import time
import random
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask-Login用
login_manager = LoginManager()

def create_app():

    """アプリケーションの初期化と設定"""
    try:        
        load_dotenv()
        
        # Flaskアプリケーションの作成
        app = Flask(__name__)        
        
        # Secret Keyの設定
        app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24))
        print(f"Secret key: {app.config['SECRET_KEY']}")

        # AWS認証情報の設定
        aws_credentials = {
            'aws_access_key_id': os.getenv("AWS_ACCESS_KEY_ID"),
            'aws_secret_access_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
            'region_name': os.getenv("AWS_REGION", "us-east-1")
        }

        # 必須環境変数のチェック
        required_env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET", "TABLE_NAME_USER", "TABLE_NAME_SCHEDULE"]
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

         # 必須環境変数をFlaskの設定に追加
        app.config["S3_BUCKET"] = os.getenv("S3_BUCKET", "default-bucket-name")
        app.config["AWS_REGION"] = os.getenv("AWS_REGION")
        app.config['S3_LOCATION'] = f"https://{app.config['S3_BUCKET']}.s3.{os.getenv('AWS_REGION')}.amazonaws.com/"
        print(f"S3_BUCKET: {app.config['S3_BUCKET']}")  # デバッグ用

         # AWSクライアントの初期化
        app.s3 = boto3.client('s3', **aws_credentials)
        app.dynamodb = boto3.resource('dynamodb', **aws_credentials)
        app.dynamodb_resource = boto3.resource('dynamodb', **aws_credentials)

        # DynamoDBテーブルの設定
        app.table_name = os.getenv("TABLE_NAME_USER")
        app.table_name_board = os.getenv("TABLE_NAME_BOARD")
        app.table_name_schedule = os.getenv("TABLE_NAME_SCHEDULE")
        app.table = app.dynamodb_resource.Table(app.table_name)
        app.table_board = app.dynamodb_resource.Table(app.table_name_board)
        app.table_schedule = app.dynamodb_resource.Table(app.table_name_schedule)

        # Flask-Loginの設定
        login_manager.init_app(app)
        login_manager.session_protection = "strong"
        login_manager.login_view = 'login'
        login_manager.login_message = 'このページにアクセスするにはログインが必要です。'

        # DynamoDBテーブルの初期化（init_tablesの実装が必要）
        # init_tables()

        logger.info("Application initialized successfully")
        return app

    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

# アプリケーションの初期化
app = create_app()


def tokyo_time():
    return datetime.now(pytz.timezone('Asia/Tokyo'))


@login_manager.user_loader
def load_user(user_id):
    app.logger.debug(f"Loading user with ID: {user_id}")

    if not user_id:
        app.logger.warning("No user_id provided to load_user")
        return None

    try:
        # DynamoDBリソースでテーブルを取得
        table = app.dynamodb.Table(app.table_name)  # テーブル名を取得
        response = table.get_item(
            Key={
                "user#user_id": user_id  # パーティションキーをそのまま指定
            }
        )

        app.logger.debug(f"DynamoDB response: {response}")

        if 'Item' in response:
            user_data = response['Item']
            user = User.from_dynamodb_item(user_data)
            app.logger.info(f"User loaded successfully: {user.__dict__}")
            return user
        else:
            app.logger.info(f"No user found for ID: {user_id}")
            return None

    except Exception as e:
        app.logger.error(f"Error loading user with ID: {user_id}: {str(e)}", exc_info=True)
        return None



class RegistrationForm(FlaskForm):
    organization = SelectField('所属', choices=[('uguis', '鶯'),('other', 'その他')], default='uguis', validators=[DataRequired(message='所属を選択してください')])
    display_name = StringField('表示名 LINE名など', validators=[DataRequired(message='表示名を入力してください'), Length(min=3, max=30, message='表示名は3文字以上30文字以下で入力してください')])
    user_name = StringField('ユーザー名', validators=[DataRequired()])
    furigana = StringField('フリガナ', validators=[DataRequired()])
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])
    email_confirm = StringField('メールアドレス確認', validators=[DataRequired(), Email(), EqualTo('email', message='メールアドレスが一致していません')])
    password = PasswordField('パスワード', validators=[DataRequired(), Length(min=8, message='パスワードは8文字以上で入力してください'), EqualTo('pass_confirm', message='パスワードが一致していません')])
    pass_confirm = PasswordField('パスワード(確認)', validators=[DataRequired()])    
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])
    guardian_name = StringField('保護者氏名')
    emergency_phone = StringField('緊急連絡先電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])
    submit = SubmitField('登録')

    def validate_guardian_name(self, field):
        if self.date_of_birth.data:
            today = date.today()
            age = today.year - self.date_of_birth.data.year - ((today.month, today.day) < (self.date_of_birth.data.month, self.date_of_birth.data.day))
            if age < 18 and not field.data:
                raise ValidationError('18歳未満の方は保護者氏名の入力が必要です')

    def validate_email(self, field):
        try:
            # emailのインデックスを使用して検索
            response = app.dynamodb.query(
                TableName=app.table_name,
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': {'S': field.data}
                }
            )
            if response.get('Items'):
                raise ValidationError('入力されたメールアドレスは既に登録されています。')
        except Exception as e:
            app.logger.error(f"Error validating email: {str(e)}")
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。')
        
        
class UpdateUserForm(FlaskForm):
    organization = SelectField('所属', choices=[('uguis', '鶯'), ('other', 'その他')], validators=[DataRequired(message='所属を選択してください')])    
    display_name = StringField('表示名 LINE名など', validators=[DataRequired(), Length(min=3, max=30)])    
    user_name = StringField('ユーザー名', validators=[DataRequired()])    
    furigana = StringField('フリガナ',  validators=[DataRequired()])    
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])    
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])    
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])    
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])    
    email_confirm = StringField('メールアドレス(確認)', validators=[DataRequired(), Email(), EqualTo('email', message='メールアドレスが一致していません')])
    password = PasswordField('パスワード', validators=[Optional(),  # パスワード変更は任意
                                                  Length(min=8, message='パスワードは8文字以上で入力してください'),EqualTo('pass_confirm', message='パスワードが一致していません')])    
    pass_confirm = PasswordField('パスワード(確認)')    
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])    
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])    
    guardian_name = StringField('保護者氏名', validators=[Optional()])
    emergency_phone = StringField('緊急連絡先電話番号', validators=[Optional(), Length(min=10, max=15, message='正しい電話番号を入力してください')])

    submit = SubmitField('更新')

    def __init__(self, user_id, dynamodb_table, *args, **kwargs):
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        self.id = f'user#{user_id}'
        self.table = dynamodb_table

    def validate_email(self, field):
        """メールアドレスの重複チェック（自分のメールアドレスは除外）"""
        try:
            response = self.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )
            
            # 検索結果があり、かつ自分以外のユーザーの場合はエラー
            if response.get('Items'):
                for item in response['Items']:
                    if item['user_id']['S'] != f'user#{self.id}':
                        raise ValidationError('このメールアドレスは既に使用されています。')
                        
        except ClientError as e:
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。')
      



class User(UserMixin):
    def __init__(self, user_id, display_name, user_name, furigana, email, password_hash, 
                 gender, date_of_birth, post_code, address, phone,guardian_name, emergency_phone, 
                 organization='uguis', administrator=False, 
                 created_at=None, updated_at=None):
        super().__init__()
        self.user_id = user_id
        self.display_name = display_name
        self.user_name = user_name
        self.furigana = furigana
        self.email = email
        self.password_hash = password_hash
        self.gender = gender
        self.date_of_birth = date_of_birth
        self.post_code = post_code
        self.address = address
        self.phone = phone
        self.guardian_name = guardian_name  # 新しいフィールドを初期化
        self.emergency_phone = emergency_phone  # 新しいフィールドを初期化
        self.organization = organization
        self.administrator = administrator
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()

    def get_id(self):
        return str(self.user_id)

    @staticmethod
    def from_dynamodb_item(item):
        def get_value(field, default=None):
            return item.get(field, default)

        return User(
            user_id=get_value('user#user_id'),
            display_name=get_value('display_name'),
            user_name=get_value('user_name'),
            furigana=get_value('furigana'),
            email=get_value('email'),
            password_hash=get_value('password'),
            gender=get_value('gender'),
            date_of_birth=get_value('date_of_birth'),
            post_code=get_value('post_code'),
            address=get_value('address'),
            phone=get_value('phone'),
            guardian_name=get_value('guardian_name', default=None),  # 新しいフィールド
            emergency_phone=get_value('emergency_phone', default=None),  # 新しいフィールド
            organization=get_value('organization', default='uguis'),
            administrator=bool(get_value('administrator', False)),
            created_at=get_value('created_at'),
            updated_at=get_value('updated_at')
        )

    def to_dynamodb_item(self):
        fields = ['user_id', 'organization', 'address', 'administrator', 'created_at', 
                  'display_name', 'email', 'furigana', 'gender', 'password', 
                  'phone', 'post_code', 'updated_at', 'user_name','guardian_name', 'emergency_phone']
        item = {field: {"S": str(getattr(self, field))} for field in fields if getattr(self, field, None)}
        item['administrator'] = {"BOOL": self.administrator}
        if self.date_of_birth:
            item['date_of_birth'] = {"S": str(self.date_of_birth)}
        return item

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @property
    def is_admin(self):
        return self.administrator


def get_user_from_dynamodb(user_id):
    try:
        # DynamoDBからユーザーデータを取得
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={"user#user_id": {"S": user_id}}
            
        )
        
        # データが存在しない場合
        if 'Item' not in response:
            app.logger.info(f"User not found in DynamoDB for user_id: {user_id}")
            return None

        item = response['Item']

        # DynamoDBのデータをUserクラスのインスタンスに変換
        user = User.from_dynamodb_item(item)
        app.logger.debug(f"User successfully loaded for user_id: {user_id}")
        return user

    except Exception as e:
        app.logger.error(f"Error fetching user from DynamoDB for user_id: {user_id}: {str(e)}", exc_info=True)
        return None  

class LoginForm(FlaskForm):
    email = StringField('メールアドレス', validators=[DataRequired(message='メールアドレスを入力してください'), Email(message='正しいメールアドレスの形式で入力してください')])
    password = PasswordField('パスワード', validators=[DataRequired(message='パスワードを入力してください')])
    remember = BooleanField('ログイン状態を保持する')
    submit = SubmitField('ログイン')

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.user = None  # self.userを初期化

    def validate_email(self, field):
        """メールアドレスの存在確認"""
        try:
            # メールアドレスでユーザーを検索
            response = app.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )
            
            items = response.get('Items', [])
            if not items:
                raise ValidationError('このメールアドレスは登録されていません')
            
            # ユーザー情報を保存（パスワード検証で使用）
            self.user = items[0]
            
        except Exception as e:
            raise ValidationError('ログイン処理中にエラーが発生しました')

    def validate_password(self, field):
        """パスワードの検証"""
        if self.user is None:
            raise ValidationError('先にメールアドレスを確認してください')
            
        if not check_password_hash(self.user['password'], field.data):
            raise ValidationError('パスワードが正しくありません')

    def get_user(self):
        """ログイン成功時のユーザー情報を返す"""
        return self.user  


class ScheduleForm(FlaskForm):
    date = DateField('日付', validators=[DataRequired()])
    day_of_week = StringField('曜日', render_kw={'readonly': True})  # 自動入力用
    
    venue = SelectField('会場', validators=[DataRequired()], choices=[
        ('', '選択してください'),
        ('北越谷 A面', '北越谷 A面'),
        ('北越谷 B面', '北越谷 B面'),
        ('北越谷 AB面', '北越谷 AB面'),
        ('越谷総合体育館 第1体育室', '越谷総合体育館 第1体育室'),
        ('越谷総合体育館 第1体育室 6面', '越谷総合体育館 第1体育室 6面'),
        ('ウィングハット', 'ウィングハット')
    ])
    
    start_time = SelectField('開始時間', validators=[DataRequired()], choices=[
        ('', '選択してください')] + 
        [(f"{h:02d}:00", f"{h:02d}:00") for h in range(9, 23)]
    )
    
    end_time = SelectField('終了時間', validators=[DataRequired()], choices=[
        ('', '選択してください')] + 
        [(f"{h:02d}:00", f"{h:02d}:00") for h in range(10, 24)]
    )
    
    submit = SubmitField('登録')


class Board_Form(FlaskForm):
    title = StringField('タイトル', validators=[DataRequired()])
    content = TextAreaField('内容', validators=[DataRequired()])
    image = FileField('ファイル', validators=[
    FileAllowed(['jpg', 'png', 'gif', 'pdf'], 'jpg, png, gif, pdfのみアップロード可能です。')])
    submit = SubmitField('投稿する')


def get_board_table():
    dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-1')
    return dynamodb.Table('bad-board-table')

# @app.route('/board', methods=['GET', 'POST'])
# def board():
#     print("Board route accessed")  # デバッグ用
#     form = Board_Form()
#     board_table = get_board_table('bad-users')
    
#     try:
#         response = board_table.scan()  # resourceインターフェースを使用
#         posts = response.get('Items', [])
#         # 受け取ったデータの構造を確認するためのデバッグ出力
#         print("Raw posts data:", posts)  
        
#         # 必要なフィールドが存在することを確認
#         formatted_posts = []
#         for post in posts:
#             formatted_post = {
#                 'user#user_id': post.get('user#user_id', ''),
#                 'post#post_id': post.get('post#post_id', ''),
#                 'title': post.get('title', ''),
#                 'content': post.get('content', ''),
#                 'created_at': post.get('created_at', ''),
#                 'display_name': post.get('display_name', '未知のユーザー'),
#                 'image_url': post.get('image_url', '')
#             }
#             formatted_posts.append(formatted_post)
        
#         # 日時でソート
#         formatted_posts.sort(key=lambda x: x['created_at'], reverse=True)
#         print(f"Retrieved and formatted {len(formatted_posts)} posts")
#         posts = formatted_posts  # 整形したデータで上書き

#     except Exception as e:
#         posts = []
#         print(f"Error retrieving posts: {str(e)}")
#         flash(f"データの取得に失敗しました: {str(e)}", "danger")

#     if form.validate_on_submit():
#         print("Form validated successfully")  # デバッグ用
#         try:
#             image_url = None
#             if form.image.data:
#                 print("Image data detected")  # デバッグ用
#                 image_file = form.image.data
#                 print(f"File info: {image_file.filename}, {image_file.content_type}")  # デバッグ用

#                 if not image_file.filename:
#                     print("No filename")  # デバッグ用
#                     flash("ファイル名が無効です", "danger")
#                     return redirect(url_for('board'))

#                 filename = secure_filename(f"{uuid.uuid4()}_{image_file.filename}")
#                 print(f"Generated filename: {filename}")  # デバッグ用

#                 try:
#                     s3_path = f"board/{filename}"
#                     print(f"Attempting S3 upload to path: {s3_path}")  # デバッグ用

#                     # ファイルポインタをリセット
#                     image_file.stream.seek(0)

#                     # S3バケット名の確認
#                     print(f"S3 bucket name: {app.config['S3_BUCKET']}")  # デバッグ用

#                     app.s3.upload_fileobj(
#                         image_file.stream,
#                         app.config['S3_BUCKET'],
#                         s3_path,
#                         ExtraArgs={
#                             'ContentType': image_file.content_type,                            
#                         }
#                     )
#                     print("S3 upload successful")  # デバッグ用
#                     image_url = f"https://{app.config['S3_BUCKET']}.s3.amazonaws.com/{s3_path}"
#                     print(f"Generated image URL: {image_url}")  # デバッグ用
#                 except Exception as e:
#                     print(f"S3 upload error: {type(e).__name__} - {str(e)}")  # デバッグ用
#                     flash(f"画像のアップロードに失敗しました: {type(e).__name__} - {str(e)}", "danger")
#                     return redirect(url_for('board'))

#             new_post = {
#                 'post_id': str(uuid.uuid4()),
#                 'title': form.title.data,
#                 'content': form.content.data,
#                 'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
#                 'image_url': image_url if image_url else ''
#             }

#             print("Attempting to save to DynamoDB")
#             new_post = {
#                     'user#user_id': current_user.user_id,
#                     'post#post_id': str(uuid.uuid4()),
#                     'title': new_post['title'],
#                     'content': new_post['content'],
#                     'created_at': new_post['created_at'],
#                     'image_url': new_post['image_url']
#                 }
            
#             print("Attempting to save to DynamoDB")  # デバッグ用
#             board_table.put_item(Item=new_post)            
#             print("DynamoDB save successful")  # デバッグ用
            
#             flash('投稿が成功しました！', 'success')
#             return redirect(url_for('board'))
            
#         except Exception as e:
#             print(f"Post creation error: {str(e)}")  # デバッグ用
#             flash(f"投稿に失敗しました: {str(e)}", "danger")

#     return render_template('board.html', form=form, posts=posts)

@app.route('/board', methods=['GET', 'POST'])

def board():
    form = Board_Form()
    board_table = get_board_table()      
    
    try:
        response = board_table.scan()
        posts = response.get('Items', [])
        print("Raw posts data:", posts)  # デバッグ用         
           

        formatted_posts = []
        for post in posts:
            formatted_post = {
                'user#user_id': post.get('user#user_id', ''),
                'post#post_id': post.get('post#post_id', ''),
                'title': post.get('title', ''),
                'content': post.get('content', ''),
                'created_at': post.get('created_at', ''),                
                'image_url': post.get('image_url', ''),
                'author_name': post.get('author_name', '名前未設定'),
            }
            formatted_posts.append(formatted_post)
        
        # 日時でソート
        formatted_posts.sort(key=lambda x: x['created_at'], reverse=True)
        print(f"Retrieved and formatted {len(formatted_posts)} posts")
        posts = formatted_posts  # 整形したデータで上書き

    except Exception as e:
        posts = []
        print(f"Error retrieving posts: {str(e)}")
        flash(f"データの取得に失敗しました: {str(e)}", "danger")

    if form.validate_on_submit():
        print("Form validated successfully")  # デバッグ用
        try:
            image_url = None
            if form.image.data:
                print("Image data detected")  # デバッグ用
                image_file = form.image.data
                print(f"File info: {image_file.filename}, {image_file.content_type}")  # デバッグ用

                if not image_file.filename:
                    print("No filename")  # デバッグ用
                    flash("ファイル名が無効です", "danger")
                    return redirect(url_for('board'))

                filename = secure_filename(f"{uuid.uuid4()}_{image_file.filename}")
                print(f"Generated filename: {filename}")  # デバッグ用

                try:
                    s3_path = f"board/{filename}"
                    print(f"Attempting S3 upload to path: {s3_path}")  # デバッグ用

                    # ファイルポインタをリセット
                    image_file.stream.seek(0)

                    # S3バケット名の確認
                    print(f"S3 bucket name: {app.config['S3_BUCKET']}")  # デバッグ用

                    app.s3.upload_fileobj(
                        image_file.stream,
                        app.config['S3_BUCKET'],
                        s3_path,
                        ExtraArgs={
                            'ContentType': image_file.content_type,                            
                        }
                    )
                    print("S3 upload successful")  # デバッグ用
                    image_url = f"https://{app.config['S3_BUCKET']}.s3.amazonaws.com/{s3_path}"
                    print(f"Generated image URL: {image_url}")  # デバッグ用
                except Exception as e:
                    print(f"S3 upload error: {type(e).__name__} - {str(e)}")  # デバッグ用
                    flash(f"画像のアップロードに失敗しました: {type(e).__name__} - {str(e)}", "danger")
                    return redirect(url_for('board'))

            print("Attempting to save to DynamoDB")
            new_post = {
                'user#user_id': current_user.user_id,
                'post#post_id': str(uuid.uuid4()),
                'title': form.title.data,
                'content': form.content.data,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'author_name': current_user.display_name,
                'image_url': image_url if image_url else ''
            }
            
            print("Attempting to save to DynamoDB")  # デバッグ用
            board_table.put_item(Item=new_post)            
            print("DynamoDB save successful")  # デバッグ用
            
            flash('投稿が成功しました！', 'success')
            return redirect(url_for('board'))
            
        except Exception as e:
            print(f"Post creation error: {str(e)}")  # デバッグ用
            flash(f"投稿に失敗しました: {str(e)}", "danger")

    return render_template('board.html', form=form, posts=posts)




def get_schedule_table():
    dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-1')  # 必要に応じてリージョンを変更
    return dynamodb.Table('Schedule')

@app.route("/", methods=['GET', 'POST'])
def index():
    form = ScheduleForm()
    if form.validate_on_submit():
        try:
            schedule_table = get_schedule_table()
            if not schedule_table:
                raise ValueError("Schedule table is not initialized")

            schedule_data = {
                'schedule_id': str(uuid.uuid4()),
                'date': form.date.data.isoformat(),
                'day_of_week': form.day_of_week.data,
                'venue': form.venue.data,
                'start_time': form.start_time.data,        # そのまま HH:MM 形式で保存
                'end_time': form.end_time.data,           # そのまま HH:MM 形式で保存
                'venue_date': f"{form.venue.data}#{form.date.data.isoformat()}",
                'created_at': datetime.now().isoformat(),                
                'status': 'active'
            }

            schedule_table.put_item(Item=schedule_data)
            flash('スケジュールが登録されました', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            app.logger.error(f"スケジュール登録エラー: {str(e)}")
            flash('スケジュールの登録中にエラーが発生しました', 'error')

    # スケジュール一覧の取得とソート
    try:
        schedules = get_schedules_with_formatting()
        schedules = sorted(schedules, key=lambda x: (x['date'], x['start_time']))
    except Exception as e:
        app.logger.error(f"スケジュール取得エラー: {str(e)}")
        schedules = []    

    return render_template(
    "index.html",
    form=form,
    schedules=schedules,
    title="鶯 | 越谷市バドミントンサークル",
    description="初心者から経験者まで楽しめる越谷市のバドミントンサークル「鶯」です。",
    canonical=url_for('index', _external=True)
    )


def get_schedules_with_formatting():
    """
    スケジュール一覧を取得し、日付をフォーマットして返す
    """
    schedule_table = get_schedule_table()
    if not schedule_table:
        raise ValueError("Schedule table is not initialized")

    # DynamoDBからスケジュールを取得し、日付をフォーマット
    response = schedule_table.scan()
    schedules = []
    for schedule in response.get('Items', []):
        date_obj = datetime.strptime(schedule['date'], "%Y-%m-%d")
        
        # 月と日をゼロ埋めしない形式で取得
        formatted_date = f"{date_obj.month}月{date_obj.day}日"
        schedule['formatted_date'] = formatted_date
        
        schedules.append(schedule)

    return schedules
  

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            current_time = datetime.now().isoformat()
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            user_id = str(uuid.uuid4())

            # メールアドレスの重複チェック用のクエリ
            email_check = app.dynamodb.query(
                TableName=app.table_name,
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': {'S': form.email.data}
                }
            )

            if email_check.get('Items'):
                app.logger.warning(f"Duplicate email registration attempt: {form.email.data}")
                flash('このメールアドレスは既に登録されています。', 'error')
                return redirect(url_for('signup'))

            # ユーザーの保存
            response = app.dynamodb.put_item(
                TableName=app.table_name,
                Item={                     
                    "user#user_id": {"S": user_id},
                    "organization": {"S": form.organization.data},  # 所属を追加
                    "address": {"S": form.address.data},
                    "administrator": {"BOOL": False},
                    "created_at": {"S": current_time},
                    "date_of_birth": {"S": form.date_of_birth.data.strftime('%Y-%m-%d')},
                    "display_name": {"S": form.display_name.data},
                    "email": {"S": form.email.data},
                    "furigana": {"S": form.furigana.data},
                    "gender": {"S": form.gender.data},
                    "password": {"S": hashed_password},
                    "phone": {"S": form.phone.data},
                    "post_code": {"S": form.post_code.data},
                    "updated_at": {"S": current_time},
                    "user_name": {"S": form.user_name.data},
                    "guardian_name": {"S": form.guardian_name.data}, 
                    "emergency_phone": {"S": form.emergency_phone.data}
                    
                },
                ReturnValues="NONE"
            )

            # ログ出力を詳細に
            app.logger.info(f"New user created - ID: {user_id}, Organization: {form.organization.data}, Email: {form.email.data}")
            
            # 成功メッセージ
            flash('アカウントが作成されました！ログインしてください。', 'success')
            return redirect(url_for('login'))
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            app.logger.error(f"DynamoDB error - Code: {error_code}, Message: {error_message}")
            
            if error_code == 'ConditionalCheckFailedException':
                flash('このメールアドレスは既に登録されています。', 'error')
            elif error_code == 'ValidationException':
                flash('入力データが無効です。', 'error')
            elif error_code == 'ResourceNotFoundException':
                flash('システムエラーが発生しました。', 'error')
                app.logger.critical(f"DynamoDB table not found: {app.table_name}")
            else:
                flash('アカウント作成中にエラーが発生しました。', 'error')
                
            return redirect(url_for('signup'))
        
        except Exception as e:
            app.logger.error(f"Unexpected error during signup: {str(e)}", exc_info=True)
            flash('予期せぬエラーが発生しました。時間をおいて再度お試しください。', 'error')
            return redirect(url_for('signup'))
            
    # フォームのバリデーションエラーの場合
    if form.errors:
        app.logger.warning(f"Form validation errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{form[field].label.text}: {error}', 'error')
    
    return render_template('signup.html', form=form)       

@app.route('/login', methods=['GET', 'POST'])
def login():

    print("あ")

    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    print("い")

    # form = LoginForm(dynamodb_table=app.table)
    form = LoginForm()
    if form.validate_on_submit():
        try:
            print("う")
            # メールアドレスでユーザーを取得
            response = app.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': form.email.data.lower()
                }
            )
            
            items = response.get('Items', [])
            user_data = items[0] if items else None
            
            if not user_data:
                app.logger.warning(f"No user found for email: {form.email.data}")
                flash('メールアドレスまたはパスワードが正しくありません。', 'error')
                return render_template('login.html', form=form)           

            try:
                user = User(
                    user_id=user_data['user#user_id'],
                    display_name=user_data['display_name'],
                    user_name=user_data['user_name'],
                    furigana=user_data['furigana'],
                    email=user_data['email'],
                    password_hash=user_data['password'],
                    gender=user_data['gender'],
                    date_of_birth=user_data['date_of_birth'],
                    post_code=user_data['post_code'],
                    address=user_data['address'],
                    phone=user_data['phone'],
                    guardian_name=user_data.get('guardian_name', None),  
                    emergency_phone=user_data.get('emergency_phone', None), 
                    administrator=user_data['administrator']
                )
                
                                
            except KeyError as e:
                app.logger.error(f"Error creating user object: {str(e)}")
                flash('ユーザーデータの読み込みに失敗しました。', 'error')
                return render_template('login.html', form=form)

            if not hasattr(user, 'check_password'):
                app.logger.error("User object missing check_password method")
                flash('ログイン処理中にエラーが発生しました。', 'error')
                return render_template('login.html', form=form)

            if user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)  
                app.logger.debug(f"Session after login: {session}")  # セッション情報を確認
                app.logger.info(f"User logged in: {user.get_id()}")
                app.logger.debug(f"Session data: {session}")                                           
                app.logger.info(f"User logged in successfully - ID: {user.user_id}, is_authenticated: {current_user.is_authenticated}")
                flash('ログインに成功しました。', 'success')
                
                next_page = request.args.get('next')
                if not next_page or not is_safe_url(next_page):
                    next_page = url_for('index')
                return redirect(next_page)            
                        
            app.logger.warning(f"Invalid password attempt for email: {form.email.data}")
            time.sleep(random.uniform(0.1, 0.3))
            flash('メールアドレスまたはパスワードが正しくありません。', 'error')
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('ログイン処理中にエラーが発生しました。', 'error')
    
    return render_template('login.html', form=form)
    

# セキュアなリダイレクト先かを確認する関数
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# セキュアなリダイレクト先かチェックする関数
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

        
@app.route("/logout")
# @login_required
def logout():
    logout_user()
    return redirect("/login")

def get_schedule_table():
    # デバッグログを追加
    region = os.getenv('AWS_REGION')
    table_name = os.getenv('TABLE_NAME_SCHEDULE', 'Schedule')
    
    app.logger.debug(f"Region: {region}")
    app.logger.debug(f"Table name: {table_name}")
    
    dynamodb = boto3.resource('dynamodb', region_name=region)
    return dynamodb.Table(table_name) 


@app.route("/edit_schedule/<schedule_id>", methods=['GET', 'POST'])
def edit_schedule(schedule_id):
    form = ScheduleForm()
    table = get_schedule_table()

    if form.validate_on_submit():  # POSTリクエストとバリデーション
        try:
            # まず現在のアイテムを取得
            response = table.scan(
                FilterExpression='schedule_id = :sid',
                ExpressionAttributeValues={
                    ':sid': schedule_id
                }
            )
            items = response.get('Items', [])
            
            if items:
                current_item = items[0]
                # 新しいvenue_dateを作成
                new_venue_date = f"{form.venue.data}#{form.date.data.isoformat()}"
                
                # 古いアイテムを削除
                table.delete_item(
                    Key={
                        'venue_date': current_item['venue_date'],
                        'schedule_id': schedule_id
                    }
                )
                
                # 新しいアイテムを作成
                new_item = {
                    'schedule_id': schedule_id,
                    'date': form.date.data.isoformat(),
                    'day_of_week': form.day_of_week.data,
                    'venue': form.venue.data,
                    'start_time': form.start_time.data,
                    'end_time': form.end_time.data,
                    'venue_date': new_venue_date,
                    'created_at': datetime.now().isoformat()
                }
                
                # 新しいアイテムを保存
                table.put_item(Item=new_item)
                
                flash('スケジュールを更新しました', 'success')
                return redirect(url_for('index'))
            
        except Exception as e:
            app.logger.error(f"スケジュール更新エラー: {str(e)}")
            flash('スケジュールの更新中にエラーが発生しました', 'error')

    try:
        # GETリクエスト時のフォーム表示用データ取得
        response = table.scan(
            FilterExpression='schedule_id = :sid',
            ExpressionAttributeValues={
                ':sid': schedule_id
            }
        )
        items = response.get('Items', [])
        
        if items and request.method == 'GET':
            schedule = items[0]
            form.date.data = datetime.strptime(schedule['date'], '%Y-%m-%d').date()
            form.day_of_week.data = schedule['day_of_week']
            form.venue.data = schedule['venue']
            form.start_time.data = schedule['start_time']
            form.end_time.data = schedule['end_time']
            
    except ClientError as e:
        app.logger.error(f"スケジュール取得エラー: {str(e)}")
        flash('スケジュールの取得中にエラーが発生しました', 'error')
        return redirect(url_for('index'))
    
    return render_template('edit_schedule.html', form=form, schedule=schedule, schedule_id=schedule_id)


@app.route("/delete_schedule/<schedule_id>", methods=['POST'])
def delete_schedule(schedule_id):
    try:
        table = get_schedule_table()
        app.logger.debug(f"Deleting schedule_id: {schedule_id}")

        # スケジュールIDでスキャン
        response = table.scan(
            FilterExpression='schedule_id = :sid',
            ExpressionAttributeValues={
                ':sid': schedule_id
            }
        )
        items = response.get('Items', [])
        
        app.logger.debug(f"Found items: {items}")
        
        if items:
            schedule = items[0]
            app.logger.debug(f"Attempting to delete: venue_date={schedule['venue_date']}, schedule_id={schedule_id}")
            
            # 両方のキーを指定して削除
            delete_response = table.delete_item(
                Key={
                    'venue_date': schedule['venue_date'],
                    'schedule_id': schedule_id
                }
            )
            app.logger.debug(f"Delete response: {delete_response}")
            
            flash('スケジュールを削除しました', 'success')
        else:
            app.logger.error(f"Schedule not found: {schedule_id}")
            flash('スケジュールが見つかりません', 'error')
            
    except Exception as e:
        app.logger.error(f"スケジュール削除エラー: {str(e)}")
        app.logger.error(f"Error details: {e}")
        flash('スケジュールの削除中にエラーが発生しました', 'error')
        
    return redirect(url_for('index'))



@app.route("/user_maintenance", methods=["GET", "POST"])
@login_required
def user_maintenance():
    try:
        # テーブルからすべてのユーザーを取得
        response = app.table.scan()
        
        # デバッグ用に取得したユーザーデータを表示
        users = response.get('Items', [])
        app.logger.info(f"Users data: {users}")
        app.logger.info(f"Retrieved {len(users)} users for maintenance page")
        for user in users:
            if 'user#user_id' in user:
                user['user_id'] = user.pop('user#user_id').replace('user#', '')

        

        return render_template("user_maintenance.html", users=users, page=1, has_next=False)

    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('ユーザー情報の取得に失敗しました。', 'error')
        return redirect(url_for('index'))
      

@app.route("/table_info")
def get_table_info():
    try:
        table = get_schedule_table()
        # テーブルの詳細情報を取得
        response = {
            'table_name': table.name,
            'key_schema': table.key_schema,
            'attribute_definitions': table.attribute_definitions,
            # サンプルデータも取得
            'sample_data': table.scan(Limit=1)['Items']
        }
        return str(response)
    except Exception as e:
        return f'Error: {str(e)}'    

    

@app.route('/account/<string:user_id>', methods=['GET', 'POST'])
def account(user_id):
    try:
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={
                'user#user_id': {'S': user_id}                
            }
        )
        user = response.get('Item')
        app.logger.debug(f"Retrieved user data: {user}")
        
        if not user:
            abort(404)

        user['user_id'] = user.pop('user#user_id')['S']
        app.logger.debug(f"Processed user data: {user}")
            
        # 現在のユーザーが対象ユーザーまたは管理者であることを確認
        # if user['user_id']['S'] != current_user.get_id() and not current_user.administrator:
        #     abort(403)

        if not user or 'user_id' not in user:
            app.logger.warning(f"Invalid user data: {user}")
            abort(404)
                
        form = UpdateUserForm(user_id=user_id, dynamodb_table=app.table)
        
        if request.method == 'GET':
              # 任意フィールドは存在チェックを行う
            if 'guardian_name' in user:
                form.guardian_name.data = user['guardian_name']['S']
            if 'emergency_phone' in user:
                form.emergency_phone.data = user['emergency_phone']['S']
            # GETリクエスト時はフォームに値を設定するだけ
            form.display_name.data = user['display_name']['S']
            form.user_name.data = user['user_name']['S']
            form.furigana.data = user['furigana']['S']
            form.email.data = user['email']['S']
            form.phone.data = user['phone']['S']
            form.post_code.data = user['post_code']['S']
            form.address.data = user['address']['S']
            form.gender.data = user['gender']['S']
            form.date_of_birth.data = datetime.strptime(user['date_of_birth']['S'], '%Y-%m-%d')            
            form.organization.data = user['organization']['S']
# 　　　　　　　任意のフィールド
            form.guardian_name.data = user.get('guardian_name', {}).get('S', '')            
            form.emergency_phone.data = user.get('emergency_phone', {}).get('S', '')
            
        elif form.validate_on_submit():  # POSTリクエストの処理
            current_time = datetime.now().isoformat()
            update_expression_parts = []
            expression_values = {}
            
            # 更新する項目を設定
            update_expression_parts.append("display_name = :display_name")
            expression_values[':display_name'] = {'S': form.display_name.data}
            # 他のフィールドも同様に追加
            
            # DynamoDBを更新
            response = app.dynamodb.update_item(
                TableName=app.table_name,
                Key={
                    'user#user_id': {'S': user_id}                    
                },               
                UpdateExpression="SET " + ", ".join(update_expression_parts),
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW"
            )
            
            flash('ユーザーアカウントが更新されました', 'success')
            return redirect(url_for('user_maintenance'))
        
        return render_template('account.html', form=form, user=user)
        
    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('データベースエラーが発生しました。', 'error')
        return redirect(url_for('user_maintenance'))   
    

@app.route("/delete_user/<string:user_id>")
def delete_user(user_id):
    try:
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={
                'user#user_id': {'S': user_id}
            }
        )
        user = response.get('Item')
        
        if not user:
            flash('ユーザーが見つかりません。', 'error')
            return redirect(url_for('user_maintenance'))
            
        # 管理者のみ削除可能
        if not current_user.administrator:
            abort(403)  # 権限がない場合は403エラー
        
        # ここで実際の削除処理を実行
        app.dynamodb.delete_item(
            TableName=app.table_name,
            Key={
                'user#user_id': {'S': user_id}
            }
        )

        flash('ユーザーアカウントが削除されました', 'success')
        return redirect(url_for('user_maintenance'))
    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('データベースエラーが発生しました。', 'error')
        return redirect(url_for('user_maintenance'))
    

@app.route("/gallery", methods=["GET", "POST"])
def gallery():
    posts = []

    if request.method == "POST":
        image = request.files.get("image")
        if image and image.filename != '':
            original_filename = secure_filename(image.filename)
            unique_filename = f"gallery/{uuid.uuid4().hex}_{original_filename}"

            img = Image.open(image)

            try:
                exif = img._getexif()
                if exif is not None:
                    for orientation in ExifTags.TAGS.keys():
                        if ExifTags.TAGS[orientation] == "Orientation":
                            break
                    orientation_value = exif.get(orientation)
                    if orientation_value == 3:
                        img = img.rotate(180, expand=True)
                    elif orientation_value == 6:
                        img = img.rotate(270, expand=True)
                    elif orientation_value == 8:
                        img = img.rotate(90, expand=True)
            except (AttributeError, KeyError, IndexError):
                # EXIFが存在しない場合はそのまま続行
                pass

            max_width = 500           
            if img.width > max_width:
                # アスペクト比を維持したままリサイズ
                new_height = int((max_width / img.width) * img.height)                
                img = img.resize((max_width, new_height), Image.LANCZOS)

            # リサイズされた画像をバイトIOオブジェクトに保存
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG')
            img_byte_arr.seek(0)

            # appを直接参照
            app.s3.upload_fileobj(
                img_byte_arr,
                app.config["S3_BUCKET"],
                unique_filename
            )
            image_url = f"{app.config['S3_LOCATION']}{unique_filename}"

            print(f"Uploaded Image URL: {image_url}")
            return redirect(url_for("gallery"))  # POST後はGETリクエストにリダイレクト

    # GETリクエスト: S3バケット内の画像を取得
    try:
        response = app.s3.list_objects_v2(Bucket=app.config["S3_BUCKET"],
                                          Prefix="gallery/")
        if "Contents" in response:
            for obj in response["Contents"]: 
                if obj['Key'] != "gallery/":
                            print(f"Found object key: {obj['Key']}")
                            posts.append({
                                "image_url": f"{app.config['S3_LOCATION']}{obj['Key']}"
                            })
    except Exception as e:
        print(f"Error fetching images from S3: {e}")

    return render_template("gallery.html", posts=posts)


@app.route("/delete_image/<filename>", methods=["POST"])
@login_required
def delete_image(filename):
    try:
        # S3から指定されたファイルを削除
        app.s3.delete_object(Bucket=app.config["S3_BUCKET"], Key=f"gallery/{filename}")
        print(f"Deleted {filename} from S3")

        # 削除成功後にアップロードページにリダイレクト
        return redirect(url_for("gallery"))

    except Exception as e:
        print(f"Error deleting {filename}: {e}")
        return "Error deleting the image", 500
    
@app.route("/uguis2024_tournament")
def uguis2024_tournament():
    return render_template("uguis2024_tournament.html")

@app.route("/videos")
def video_link():
    return render_template("video_link.html")    

@app.route("/<int:id>/delete")
# @login_required
def delete(id):
    post = Post.query.get(id)
    db.session.delete(post)
    db.session.commit()
    return redirect("/")  


if __name__ == "__main__":
    with app.app_context():    
        pass    
    app.run(debug=True)