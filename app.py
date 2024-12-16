from flask import Flask
from flask_caching import Cache
from flask_wtf import FlaskForm
from flask import render_template, request, redirect, url_for, flash, abort, session
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError, StringField,  TextAreaField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_wtf.file import FileField, FileAllowed, FileSize
import pytz
import os
import boto3
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime, date
import io
from PIL import Image, ExifTags
from dateutil import parser, relativedelta
from botocore.exceptions import ClientError
import logging
import time
import random
from urllib.parse import urlparse, urljoin

from dotenv import load_dotenv

cache = Cache()

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

        # キャッシュの設定と初期化
        app.config["CACHE_TYPE"] = "simple"
        app.config["CACHE_DEFAULT_TIMEOUT"] = 1800
        cache.init_app(app)
       

        # AWS認証情報の設定
        aws_credentials = {
            'aws_access_key_id': os.getenv("AWS_ACCESS_KEY_ID"),
            'aws_secret_access_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
            'region_name': os.getenv("AWS_REGION", "us-east-1")
        }

        # 必須環境変数のチェック
        required_env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET", "TABLE_NAME_USER", "TABLE_NAME_SCHEDULE","TABLE_NAME_BOARD"]
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

@app.context_processor
def inject_canonical_url():
    """
    テンプレートにカノニカルURLを提供する
    """
    canonical_url = request.base_url  # クエリパラメータを除外したURLを取得
    return dict(canonical_url=canonical_url)


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
                "user#user_id": user_id,   # パーティションキーをそのまま指定
            }
        )        

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
    organization = SelectField('所属', choices=[('鶯', '鶯'),('other', 'その他')], default='鶯', validators=[DataRequired(message='所属を選択してください')])
    display_name = StringField('表示名 LINE名など', validators=[DataRequired(message='表示名を入力してください'), Length(min=1, max=30, message='表示名は1文字以上30文字以下で入力してください')])
    user_name = StringField('ユーザー名', validators=[DataRequired()])
    furigana = StringField('フリガナ', validators=[DataRequired()])
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])
    email_confirm = StringField('メールアドレス確認', validators=[DataRequired(), Email(), EqualTo('email', message='メールアドレスが一致していません')])
    password = PasswordField('8文字以上のパスワード', validators=[DataRequired(), Length(min=8, message='パスワードは8文字以上で入力してください'), EqualTo('pass_confirm', message='パスワードが一致していません')])
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
            table = app.dynamodb.Table(app.table_name)
            # emailのインデックスを使用して検索
            # email-indexを使用してメールアドレスを検索
            response = table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )
            if response.get('Items'):
                raise ValidationError('入力されたメールアドレスは既に登録されています。')
        except Exception as e:
            app.logger.error(f"Error validating email: {str(e)}")
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。')
        
        
class UpdateUserForm(FlaskForm):
    organization = SelectField('所属', choices=[('鶯', '鶯'),('other', 'その他')], default='鶯', validators=[DataRequired(message='所属を選択してください')])
    display_name = StringField('表示名 LINE名など', validators=[DataRequired(), Length(min=1, max=30)])
    user_name = StringField('ユーザー名', validators=[DataRequired()])
    furigana = StringField('フリガナ', validators=[DataRequired()])
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15)])
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7)])
    address = StringField('住所', validators=[DataRequired(), Length(max=100)])    
    email = StringField('メールアドレス', validators=[DataRequired(), Email()])
    email_confirm = StringField('確認用メールアドレス', validators=[Optional(), Email()])
    password = PasswordField('パスワード', validators=[Optional(), Length(min=8), EqualTo('pass_confirm', message='パスワードが一致していません')])
    pass_confirm = PasswordField('パスワード(確認)')
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])
    guardian_name = StringField('保護者氏名', validators=[Optional()])
    emergency_phone = StringField('緊急連絡先電話番号', validators=[Optional(), Length(min=10, max=15)])
    submit = SubmitField('更新')

    def __init__(self, user_id, dynamodb_table, *args, **kwargs):
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        self.id = f'user#{user_id}'
        self.table = dynamodb_table

         # フィールドを初期化
        self.email_readonly = True  # デフォルトでは編集不可

    def validate_email_confirm(self, field):
        # フォームでemailが変更されていない場合は何もしない
        if self.email_readonly:
            return

        # email_confirmが空の場合のエラーチェック
        if not field.data:
            raise ValidationError('確認用メールアドレスを入力してください。')

        # email_confirmが入力されている場合のみ一致を確認
        if field.data != self.email.data:
            raise ValidationError('メールアドレスが一致していません。再度入力してください。')
            

    def validate_email(self, field):
        # メールアドレスが変更されていない場合はバリデーションをスキップ
        if self.email_readonly or not field.data:
            return

        try:
            # DynamoDBにクエリを投げて重複チェックを実行
            response = self.table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': field.data
                }
            )

            app.logger.debug(f"Query response: {response}")

            if response.get('Items'):
                for item in response['Items']:
                    user_id = item.get('user#user_id') or item.get('user_id')
                    if user_id and user_id != self.id:
                        raise ValidationError('このメールアドレスは既に使用されています。他のメールアドレスをお試しください。')
        except ClientError as e:
            app.logger.error(f"Error querying DynamoDB: {e}")
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。管理者にお問い合わせください。')
        except Exception as e:
            app.logger.error(f"Unexpected error querying DynamoDB: {e}")
            raise ValidationError('予期しないエラーが発生しました。管理者にお問い合わせください。')


class TempRegistrationForm(FlaskForm):
    # 表示名
    display_name = StringField(
        '表示名', 
        validators=[
            DataRequired(message='表示名を入力してください'),
            Length(min=1, max=30, message='表示名は1文字以上30文字以下で入力してください')
        ]
    )

    # 名前
    user_name = StringField(
        '名前',
        validators=[
            DataRequired(message='名前を入力してください'),
            Length(min=1, max=30, message='名前は1文字以上30文字以下で入力してください')
        ]
    )
    
    # 性別
    gender = SelectField(
        '性別', 
        choices=[
            ('', '性別を選択してください'),
            ('male', '男性'),
            ('female', '女性')
        ], 
        validators=[
            DataRequired(message='性別を選択してください')
        ]
    )
    
    # バドミントン歴
    badminton_experience = SelectField(
        'バドミントン歴', 
        choices=[
            ('', 'バドミントン歴を選択してください'),
            ('no_experience', '未経験者'),
            ('less_than_1_year', '1年未満'),
            ('1_to_3_years', '1年以上～3年未満'),
            ('more_than_3_years', '3年以上')
        ], 
        validators=[
            DataRequired(message='バドミントン歴を選択してください')
        ]
    )
    
    # メールアドレス
    email = StringField(
        'メールアドレス', 
        validators=[
            DataRequired(message='メールアドレスを入力してください'),
            Email(message='正しいメールアドレスを入力してください')
        ]
    )
    
    # パスワード
    password = PasswordField(
        'パスワード', 
        validators=[
            DataRequired(message='パスワードを入力してください'),
            Length(min=8, message='パスワードは8文字以上で入力してください')
        ]
    )
    
    # 登録ボタン
    submit = SubmitField('仮登録')


@app.route('/temp_register', methods=['GET', 'POST'])
def temp_register():
    form = TempRegistrationForm()
    if form.validate_on_submit():
        try:
            current_time = datetime.now().isoformat()  # UTCで統一
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            user_id = str(uuid.uuid4())

            table = app.dynamodb.Table(app.table_name)

            temp_data = {
                "user#user_id": user_id,
                "display_name": form.display_name.data,
                "user_name": form.user_name.data,
                "gender": form.gender.data,
                "badminton_experience": form.badminton_experience.data,
                "email": form.email.data,
                "password": hashed_password,
                "organization": "仮登録",
                "created_at": current_time,
                "administrator": False
            }

            # DynamoDBに保存
            table.put_item(Item=temp_data)

            # 仮登録成功後、ログインページにリダイレクト
            flash("仮登録が完了しました。ログインしてください。", "success")
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"DynamoDBへの登録中にエラーが発生しました: {e}", exc_info=True)
            flash(f"登録中にエラーが発生しました: {str(e)}", 'danger')

    return render_template('temp_register.html', form=form) 


@app.route('/schedule/<string:schedule_id>/join', methods=['POST'])
@login_required
def join_schedule(schedule_id):
    try:
        venue_date = request.form.get('venue_date')
        if not venue_date:
            flash("会場情報が見つかりません。", "danger")
            return redirect(url_for('index'))

        # DynamoDBから該当のスケジュールを取得
        schedule_table = get_schedule_table()
        response = schedule_table.get_item(
            Key={
                'venue_date': venue_date,
                'schedule_id': schedule_id
            }
        )

        schedule = response.get('Item')
        if not schedule:
            flash("スケジュールが見つかりません。", "danger")
            return redirect(url_for('index'))

        # 参加者リストに現在のユーザーIDを追加
        participants = schedule.get('participants', [])
        if current_user.id not in participants:
            participants.append(current_user.id)
            schedule_table.update_item(
                Key={
                    'venue_date': venue_date,
                    'schedule_id': schedule_id
                },
                UpdateExpression="SET participants = :participants",
                ExpressionAttributeValues={':participants': participants}
            )
            flash("参加登録が完了しました！", "success")

        return redirect(url_for('index'))  # リロードしてテンプレートを再描画

    except Exception as e:
        app.logger.error(f"Error joining schedule: {e}", exc_info=True)
        flash("エラーが発生しました。", "danger")
        return redirect(url_for('index'))


class User(UserMixin):
    def __init__(self, user_id, display_name, user_name, furigana, email, password_hash,
                 gender, date_of_birth, post_code, address, phone, guardian_name, emergency_phone, 
                 organization='other', administrator=False, 
                 created_at=None, updated_at=None):
        super().__init__()
        self.id = user_id
        self.display_name = display_name
        self.user_name = user_name
        self.furigana = furigana
        self.email = email 
        self._password_hash = password_hash
        self.gender = gender
        self.date_of_birth = date_of_birth
        self.post_code = post_code
        self.address = address
        self.phone = phone
        self.guardian_name = guardian_name 
        self.emergency_phone = emergency_phone 
        self.organization = organization
        self.administrator = administrator
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()

    def check_password(self, password):
        return check_password_hash(self._password_hash, password)  # _password_hashを使用

    @property
    def is_admin(self):
        return self.administrator    
   

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
            password_hash=get_value('password'),  # 修正：password フィールドを取得
            gender=get_value('gender'),
            date_of_birth=get_value('date_of_birth'),
            post_code=get_value('post_code'),
            address=get_value('address'),
            phone=get_value('phone'),
            guardian_name=get_value('guardian_name', default=None),
            emergency_phone=get_value('emergency_phone', default=None),
            organization=get_value('organization', default='other'),
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
            # ユーザーをロード
            app.logger.debug(f"User found for email: {field.data}")       
           
        
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            raise ValidationError('ログイン処理中にエラーが発生しました')

    def validate_password(self, field):
        """パスワードの検証"""
        if not self.user:
            raise ValidationError('先にメールアドレスを確認してください')

        stored_hash = self.user.get('password')
        app.logger.debug(f"Retrieved user: {self.user}")
        app.logger.debug(f"Stored hash: {stored_hash}")
        if not stored_hash:
            app.logger.error("No password hash found in user data")
            raise ValidationError('登録情報が正しくありません')

        app.logger.debug("Validating password against stored hash")
        if not check_password_hash(stored_hash, field.data):
            app.logger.debug("Password validation failed")
            raise ValidationError('パスワードが正しくありません')


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
    title = StringField('タイトル', 
        validators=[
            DataRequired(message='タイトルを入力してください'),
            Length(max=100, message='タイトルは100文字以内で入力してください')
        ])
    
    content = TextAreaField('内容', 
        validators=[
            DataRequired(message='内容を入力してください'),
            Length(max=2000, message='内容は2000文字以内で入力してください')
        ])
    
    admin_memo = TextAreaField('管理者用メモ', validators=[Optional()])  # 追加
    
    image = FileField('ファイル', 
        validators=[
            FileAllowed(
                ['jpg', 'jpeg', 'png', 'gif', 'pdf'],
                'jpg, jpeg, png, gif, pdfファイルのみアップロード可能です'
            ),
            FileSize(max_size=5 * 1024 * 1024, message='ファイルサイズは5MB以内にしてください')  # 5MB制限
        ])
    
    remove_image = BooleanField('画像を削除する')
    
    submit = SubmitField('投稿する')

    def validate_image(self, field):
        if field.data:
            filename = field.data.filename.lower()
            if not any(filename.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.pdf']):
                raise ValidationError('許可されていないファイル形式です')

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
            cache.delete_memoized(get_schedules_with_formatting)
            flash('スケジュールが登録されました', 'success')
            return redirect(url_for('index'))

        except Exception as e:
           
            flash('スケジュールの登録中にエラーが発生しました', 'error')

    # スケジュール一覧の取得とソート
    try:
        schedules = get_schedules_with_formatting()
        schedules = sorted(schedules, key=lambda x: (x['date'], x['start_time']))
    except Exception as e:        
        schedules = []    

    return render_template(
    "index.html",
    form=form,
    schedules=schedules,
    title="鶯 | 越谷市バドミントンサークル",
    description="初心者から経験者まで楽しめる越谷市のバドミントンサークル「鶯」です。",
    canonical=url_for('index', _external=True)
    )

@cache.memoize(timeout=1800)
def get_schedules_with_formatting():
    logger.debug("Checking cache for schedules")
    cache_key = "get_schedules_with_formatting"
    logger.debug(f"Checking cache for key: {cache_key}")

    print("DynamoDBからデータを取得中...")
    schedule_table = get_schedule_table()
    if not schedule_table:
        raise ValueError("Schedule table is not initialized")

    response = schedule_table.scan()
    schedules = []
    for schedule in response.get('Items', []):
        # date_obj = datetime.strptime(schedule['date'], "%Y-%m-%d")
        date_obj = parser.parse(schedule['date'])
        
        formatted_date = f"{date_obj.month}月{date_obj.day}日"
        schedule['formatted_date'] = formatted_date
        
        schedules.append(schedule)

    logger.debug(f"Caching data for key: {cache_key}")
    return schedules

@app.template_filter('format_date')
def format_date(value):
    """日付を 'MM/DD' 形式にフォーマット"""
    try:
        date_obj = datetime.fromisoformat(value)  # ISO 形式から日付オブジェクトに変換
        return date_obj.strftime('%m/%d')        # MM/DD フォーマットに変換
    except ValueError:
        return value  # 変換できない場合はそのまま返す

@app.route('/clear-cache')
def clear_cache():
    cache.delete_memoized(get_schedules_with_formatting)
    return 'キャッシュをクリアしました'  

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            current_time = datetime.now().isoformat()
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            user_id = str(uuid.uuid4())          

            table = app.dynamodb.Table(app.table_name) 

            # メールアドレスの重複チェック用のクエリ
            email_check = table.query(
                IndexName='email-index',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={
                    ':email': form.email.data
                }
            )

            if email_check.get('Items'):
                app.logger.warning(f"Duplicate email registration attempt: {form.email.data}")
                flash('このメールアドレスは既に登録されています。', 'error')
                return redirect(url_for('signup'))         

            app.table.put_item(
                Item={
                    "user#user_id": user_id,  # 注意: DynamoDBリソースAPIではデータ型を指定する必要がありません
                    "organization": form.organization.data,
                    "address": form.address.data,
                    "administrator": False,
                    "created_at": current_time,
                    "date_of_birth": form.date_of_birth.data.strftime('%Y-%m-%d'),
                    "display_name": form.display_name.data,
                    "email": form.email.data,
                    "furigana": form.furigana.data,
                    "gender": form.gender.data,
                    "password": hashed_password,
                    "phone": form.phone.data,
                    "post_code": form.post_code.data,
                    "updated_at": current_time,
                    "user_name": form.user_name.data,
                    "guardian_name": form.guardian_name.data,
                    "emergency_phone": form.emergency_phone.data
                },
                ConditionExpression='attribute_not_exists(user_id)'
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

    if current_user.is_authenticated:
        return redirect(url_for('index')) 

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
                    furigana=user_data.get('furigana', None),
                    email=user_data['email'],
                    password_hash=user_data['password'],
                    gender=user_data['gender'],
                    date_of_birth=user_data.get('date_of_birth', None),
                    post_code=user_data.get('post_code', None),
                    address=user_data.get('address',None),
                    phone=user_data.get('phone', None),
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
                app.logger.info(f"User logged in successfully - ID: {user.id}, is_authenticated: {current_user.is_authenticated}")
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
    return redirect("/")

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
        table = app.dynamodb.Table(app.table_name)
        response = table.get_item(Key={'user#user_id': user_id})
        user = response.get('Item')

        if not user:
            abort(404)

        user['user_id'] = user.pop('user#user_id')
        app.logger.info(f"User loaded successfully: {user_id}")

        form = UpdateUserForm(user_id=user_id, dynamodb_table=app.table)

        if request.method == 'GET':
            app.logger.debug("Initializing form with GET request.")
            form.display_name.data = user['display_name']
            form.user_name.data = user['user_name']
            form.furigana.data = user['furigana']
            form.email.data = user['email']
            form.phone.data = user['phone']
            form.post_code.data = user['post_code']
            form.address.data = user['address']
            form.gender.data = user['gender']
            try:
                form.date_of_birth.data = datetime.strptime(user['date_of_birth'], '%Y-%m-%d')
            except (ValueError, KeyError) as e:
                app.logger.error(f"Invalid date format for user {user_id}: {e}")
                form.date_of_birth.data = None
            form.organization.data = user['organization']
            form.guardian_name.data = user.get('guardian_name', '')
            form.emergency_phone.data = user.get('emergency_phone', '')
            return render_template('account.html', form=form, user=user)

        if request.method == 'POST' and form.validate_on_submit():
            app.logger.debug("Form validation passed.")
            app.logger.debug(f"Form data: {form.data}")

            current_time = datetime.now().isoformat()
            update_expression_parts = []
            expression_values = {}

            fields_to_update = [
                ('display_name', 'display_name'),
                ('user_name', 'user_name'),
                ('furigana', 'furigana'),
                ('email', 'email'),
                ('phone', 'phone'),
                ('post_code', 'post_code'),
                ('address', 'address'),
                ('gender', 'gender'),
                ('organization', 'organization'),
                ('guardian_name', 'guardian_name'),
                ('emergency_phone', 'emergency_phone')
            ]

            for field_name, db_field in fields_to_update:
                field_value = getattr(form, field_name).data
                if field_value:
                    update_expression_parts.append(f"{db_field} = :{db_field}")
                    expression_values[f":{db_field}"] = field_value

            if form.date_of_birth.data:
                date_str = form.date_of_birth.data.strftime('%Y-%m-%d')
                update_expression_parts.append("date_of_birth = :date_of_birth")
                expression_values[':date_of_birth'] = date_str

            if form.password.data:
                hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
                if hashed_password != user.get('password'):  # 現在の値と異なる場合のみ更新
                    update_expression_parts.append("password = :password")
                    expression_values[':password'] = hashed_password
                    app.logger.debug(f"Password updated to: {hashed_password}")

            update_expression_parts.append("updated_at = :updated_at")
            expression_values[':updated_at'] = current_time

            if update_expression_parts:
                try:
                    update_expression = "SET " + ", ".join(update_expression_parts)
                    app.logger.debug(f"Final update expression: {update_expression}")
                    response = table.update_item(
                        Key={'user#user_id': user_id},
                        UpdateExpression=update_expression,
                        ExpressionAttributeValues=expression_values,
                        ReturnValues="ALL_NEW"
                    )
                    app.logger.info(f"User {user_id} updated successfully: {response}")
                    updated_user = table.get_item(Key={'user#user_id': user_id}, ConsistentRead=True).get('Item')
                    app.logger.debug(f"Updated user data: {updated_user}")
                except Exception as e:
                    app.logger.error(f"Error updating user in DynamoDB for user {user_id}: {e}", exc_info=True)
                    flash('データベースの更新中にエラーが発生しました。', 'error')
                    return redirect(url_for('account', user_id=user_id))

            flash('更新する項目がありません。', 'info')
            return redirect(url_for('account', user_id=user_id))

        app.logger.debug(f"Validation failed. Errors: {form.errors}")
        for field, errors in form.errors.items():
            app.logger.debug(f"Field: {field}, Errors: {errors}")
        flash('入力内容にエラーがあります。修正してください。', 'error')
        return render_template('account.html', form=form, user=user)

    except Exception as e:
        app.logger.error(f"Unexpected error in account route for user {user_id}: {e}", exc_info=True)
        flash('予期せぬエラーが発生しました。', 'error')
        return redirect(url_for('index'))
                

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
    



def get_board_table():
    """
    DynamoDB テーブルを取得する関数。
    テーブル名とリージョンは環境変数を使用して設定。
    """
    # 環境変数からリージョンとテーブル名を取得
    region = os.getenv('AWS_REGION', 'ap-northeast-1')  # リージョンが未設定の場合、デフォルト値を使用
    table_name = os.getenv('TABLE_NAME_BOARD')  # テーブル名が未設定の場合、デフォルト値を使用

    # DynamoDBリソースを初期化
    dynamodb = boto3.resource('dynamodb', region_name=region)

    # テーブルを返す
    return dynamodb.Table(table_name)


@app.route('/board', methods=['GET', 'POST'])
def board():
    form = Board_Form()
    board_table = get_board_table()      
    
    try:
        response = board_table.scan()
        posts = response.get('Items', [])
        
        # 更新日時でソート（降順）
        posts.sort(key=lambda x: x.get('updated_at', ''), reverse=True)

        formatted_posts = []
        for post in posts:
            print(f"Raw post data: {post}")

            try:
                # image_urlのキーの存在確認と、空文字列やNoneの場合の処理
                image_url = post.get('image_url', '') or ''

                formatted_post = {
                    'post_user_id': post.get('post_user_id', ''),
                    'user#user_id': post.get('user#user_id', ''),
                    'post#post_id': post.get('post#post_id', ''),
                    'title': post.get('title', ''),
                    'content': post.get('content', ''),                   
                    'created_at': post.get('created_at'),
                    'updated_at': post.get('updated_at'),
                    'image_url': image_url,
                    'author_name': post.get('author_name', '名前未設定'),
                    'admin_memo': post.get('admin_memo', '')
                }
                print(f"Formatted post: {formatted_post}")
                formatted_posts.append(formatted_post)

            except Exception as e:
                logger.error(f"Error formatting post {post.get('post#post_id')}: {str(e)}")
                try:
                    post['created_at_display'] = post.get('created_at', '')
                    post['updated_at_display'] = post.get('updated_at', '')
                except:
                    pass
                formatted_posts.append(post)

        # ソート用の関数（ループの外で定義）
        def get_sort_datetime(post):
            try:
                sort_date = post.get('updated_at') or post.get('created_at')
                return datetime.fromisoformat(sort_date)
            except:
                return datetime.min
        

    except Exception as e:
        formatted_posts = []
        logger.error(f"Error retrieving posts: {str(e)}")
        flash(f"データの取得に失敗しました: {str(e)}", "danger")
    

    if form.validate_on_submit():
        print("Form validated successfully")
        try:
            image_url = ''  # デフォルト値を空文字列に設定
            if form.image.data:
                print(f"Image data detected: {form.image.data}")
                image_file = form.image.data

                if not image_file.filename:
                    print("No filename provided")
                    flash("ファイル名が無効です", "danger")
                    return redirect(url_for('board'))

                try:
                    # 画像を開いて処理
                    img = Image.open(image_file)

                    # EXIF情報に基づいて画像を回転
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
                        pass

                    # リサイズ処理
                    max_width = 800
                    if img.width > max_width:
                        new_height = int((max_width / img.width) * img.height)
                        img = img.resize((max_width, new_height), Image.LANCZOS)

                    # 処理した画像をバイトストリームに保存
                    img_byte_arr = io.BytesIO()
                    img.save(img_byte_arr, format='JPEG', quality=85)
                    img_byte_arr.seek(0)

                    # S3にアップロード
                    filename = secure_filename(f"{uuid.uuid4()}_{image_file.filename}")
                    s3_path = f"board/{filename}"
                    
                    app.s3.upload_fileobj(
                        img_byte_arr,
                        app.config['S3_BUCKET'],
                        s3_path,
                        ExtraArgs={'ContentType': 'image/jpeg'}
                    )
                    
                    image_url = f"https://{app.config['S3_BUCKET']}.s3.amazonaws.com/{s3_path}"
                    print(f"Generated image URL: {image_url}")

                except Exception as e:
                    print(f"S3 upload failed: {str(e)}")
                    flash(f"画像のアップロードに失敗しました: {str(e)}", "danger")
                    return redirect(url_for('board'))

            print("Preparing data for DynamoDB")
            post_id = str(uuid.uuid4())  # 一意の投稿IDを生成
            updated_at = datetime.now().isoformat()  # 現在時刻を取得

            # ソートキーとして使用する post_updated_key を生成
            post_updated_key = f"{post_id}#{updated_at}"
            # post_user_id を生成
            post_user_id = f"{current_user.id}_{post_id}"

            new_post = {
                'post_user_id': post_user_id,  # パーティションキー
                'updated_at': updated_at,  # ソートキーとして更新日時を使用
                'post#post_id': post_id,  # 一意の投稿ID
                'user#user_id': current_user.id,  # ユーザーID（補助的な情報）
                'title': form.title.data,  # 投稿タイトル
                'content': form.content.data,  # 投稿内容
                'created_at': updated_at,  # 作成日時
                'author_name': current_user.display_name,  # 投稿者名
                'image_url': image_url  # 画像URL
            }
            # 管理者の場合、admin_memo を追加
            if current_user.is_admin:
                new_post['admin_memo'] = form.admin_memo.data or ''  # フォームに入力がない場合は空文字列を設定
            print(f"New post data to save: {new_post}")           
                
            try:
                # DynamoDBにデータを保存
                board_table.put_item(Item=new_post)  # 必要なキー構造に合わせたデータを保存
                print(f"Post saved to DynamoDB with image_url: {image_url}")
                flash('投稿が成功しました！', 'success')
                return redirect(url_for('board'))

            except Exception as e:
                # DynamoDBの保存中にエラーが発生した場合
                print(f"Error saving post to DynamoDB: {str(e)}")
                flash(f"データの保存に失敗しました: {str(e)}", "danger")
                return redirect(url_for('board'))

        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            flash(f"予期しないエラーが発生しました: {str(e)}", "danger")
            return redirect(url_for('board'))
        
    return render_template('board.html', form=form, posts=formatted_posts)



@app.route('/post/<string:post_user_id>/update-memo', methods=['POST'])
@login_required
def update_admin_memo(post_user_id):
    try:
        print("か")
        updated_at = request.form.get('updated_at', None)
        admin_memo = request.form.get('admin_memo', '').strip()

        # ログでデバッグ
        app.logger.debug(f"Received post_user_id: {post_user_id}")
        app.logger.debug(f"Received updated_at: {updated_at}")
        app.logger.debug(f"Received admin_memo: {admin_memo}")

        if not updated_at:
            flash('更新日時が指定されていません', 'danger')
            return redirect(url_for('board'))

        board_table = get_board_table()  # DynamoDBテーブル取得関数

        # DynamoDBから投稿を取得
        response = board_table.get_item(
            Key={
                'post_user_id': post_user_id,
                'updated_at': updated_at
            }
        )
        item = response.get('Item')

        if not item:
            flash('投稿が見つかりません', 'danger')
            return redirect(url_for('board'))

        # DynamoDBで投稿を更新
        board_table.update_item(
            Key={
                'post_user_id': post_user_id,
                'updated_at': updated_at
            },
            UpdateExpression="SET admin_memo = :memo",
            ExpressionAttributeValues={
                ':memo': admin_memo
            }
        )

        flash('管理者メモを更新しました', 'success')
        return redirect(url_for('board'))

    except Exception as e:
        app.logger.error(f"Error updating admin memo: {e}")
        flash('管理者メモの更新中にエラーが発生しました', 'danger')
        return redirect(url_for('board'))


@app.route('/board/delete/<string:post_user_id>', methods=['POST'])
@login_required
def delete_post(post_user_id):
    board_table = get_board_table()
    updated_at = request.form.get('updated_at')  # 更新日時をフォームから取得

    if not updated_at:
        flash("更新日時が指定されていません", "danger")
        return redirect(url_for('board'))

    logger.info(f"Deleting post: {post_user_id}, updated_at: {updated_at}")

    try:
        # 投稿を取得
        response = board_table.get_item(
            Key={
                'post_user_id': post_user_id,
                'updated_at': updated_at
            }
        )

        if 'Item' not in response:
            logger.error(f"Post not found: post_user_id={post_user_id}, updated_at={updated_at}")
            flash("投稿が見つかりませんでした", "danger")
            return redirect(url_for('board'))

        post = response['Item']

        # ユーザーの権限を確認
        if post['user#user_id'] != current_user.id:
            logger.error(f"Permission denied. User: {current_user.id}, Post owner: {post['user#user_id']}")
            flash("この投稿を削除する権限がありません", "danger")
            return redirect(url_for('board'))

        # 画像の削除
        image_url = post.get('image_url')
        if image_url:
            try:
                s3_path = image_url.split('.com/')[-1]
                app.s3.delete_object(Bucket=app.config['S3_BUCKET'], Key=s3_path)
                logger.info(f"Image deleted successfully: {s3_path}")
            except Exception as e:
                logger.error(f"Failed to delete image: {e}")

        # 投稿の削除
        board_table.delete_item(
            Key={
                'post_user_id': post_user_id,
                'updated_at': updated_at
            }
        )
        logger.info(f"Post deleted successfully: {post_user_id}, updated_at: {updated_at}")
        flash("投稿を削除しました", "success")

    except Exception as e:
        logger.error(f"Delete failed: {e}")
        flash("削除中にエラーが発生しました", "danger")

    return redirect(url_for('board'))


@app.route('/board/edit/<string:post_user_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_user_id):
    # リクエストパラメータからupdated_atを取得
    updated_at = request.args.get('updated_at')
    if not updated_at:
        print("Error: updated_at is missing from the request.")
        flash('更新日時が指定されていません', 'danger')
        return redirect(url_for('board'))

    try:
        print(f"Editing post with post_user_id: {post_user_id}, updated_at: {updated_at}")
        board_table = get_board_table()
        form = Board_Form()

        # DynamoDB から投稿を取得
        response = board_table.get_item(
            Key={
                'post_user_id': post_user_id,
                'updated_at': updated_at
            }
        )
        if 'Item' not in response:
            print("Post not found.")
            flash('投稿が見つかりませんでした', 'danger')
            return redirect(url_for('board'))

        post = response['Item']
        print(f"Fetched post: {post}")

        # 投稿者本人かチェック
        if post['user#user_id'] != current_user.id:
            print(f"Permission denied. Post user: {post['user#user_id']}, Current user: {current_user.id}")
            flash('この投稿を編集する権限がありません', 'danger')
            return redirect(url_for('board'))

        # 編集ロジック
        if form.validate_on_submit():
            new_updated_at = datetime.now(pytz.timezone('Asia/Tokyo')).isoformat()

            # 新しい項目を作成
            new_post = post.copy()
            new_post['title'] = form.title.data
            new_post['content'] = form.content.data
            new_post['updated_at'] = new_updated_at

            if current_user.is_admin:
                new_post['admin_memo'] = form.admin_memo.data or ''  # None の場合は空文字列を設定

            try:
                # トランザクションで更新処理を実行
                with board_table.batch_writer() as batch:
                    # 古い項目を削除
                    batch.delete_item(
                        Key={
                            'post_user_id': post_user_id,
                            'updated_at': updated_at
                        }
                    )
                    # 新しい項目を追加
                    batch.put_item(Item=new_post)

                print(f"Post updated successfully. New updated_at: {new_updated_at}")
                flash('投稿を更新しました', 'success')
                return redirect(url_for('board'))

            except Exception as e:
                print(f"Failed to update post: {e}")
                flash('投稿の更新に失敗しました', 'danger')
                return redirect(url_for('board'))

        # GETリクエスト時、フォームにデータを設定
        form.title.data = post.get('title', '')
        form.content.data = post.get('content', '')
        if current_user.is_admin:
            form.admin_memo.data = post.get('admin_memo', '')

        return render_template('edit_post.html', form=form, post=post)

    except Exception as e:
        print(f"Exception in edit_post: {e}")
        flash(f"エラーが発生しました: {e}", 'danger')
        return redirect(url_for('board'))
    
    
@app.route("/uguis2024_tournament")
def uguis2024_tournament():
    return render_template("uguis2024_tournament.html")

@app.route("/videos")
def video_link():
    return render_template("video_link.html")  


if __name__ == "__main__":
    with app.app_context():    
        pass    
    app.run(debug=True)