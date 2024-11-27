from flask import Flask

from flask import render_template, request, redirect, url_for, flash, abort, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash

import pytz
import os
import boto3
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime, date
import io
from PIL import Image
from dateutil.relativedelta import relativedelta
from botocore.exceptions import ClientError
from init_db import init_tables  # init_counter_tableから変更
import logging
import time
import random
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv

# ロギングの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# グローバル変数の定義
app = Flask(__name__)
login_manager = LoginManager()

def create_app():
    """アプリケーションの初期化と設定"""
    try:        
        load_dotenv()
        
        app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")                 
        print(f"Secret key: {app.config['SECRET_KEY']}")    
        

        aws_credentials = {
            'aws_access_key_id': os.getenv("AWS_ACCESS_KEY_ID"),
            'aws_secret_access_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
            'region_name': os.getenv("AWS_REGION")
        }
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_credentials['aws_access_key_id'],
            aws_secret_access_key=aws_credentials['aws_secret_access_key'],
            region_name=aws_credentials['region_name']
        )       
              
        
        # 必須環境変数のチェック
        required_env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_BUCKET"]
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

        # AWSクライアントの初期化
        app.s3 = boto3.client('s3', **aws_credentials)
        app.dynamodb = boto3.client('dynamodb', **aws_credentials)
        app.dynamodb_resource = boto3.resource('dynamodb', **aws_credentials)
        
        # テーブル名の設定
        app.table_name = os.getenv("TABLE_NAME")
        app.table_name_schedule = os.getenv("TABLE_NAME_SCHEDULE")

        # DynamoDBリソースからテーブルを取得
        app.table = app.dynamodb_resource.Table(app.table_name)  # "bad-users"
        app.table_schedule = app.dynamodb_resource.Table(app.table_name_schedule)  # "Schedule"

        # Flask-Loginの設定
        login_manager.init_app(app)
        login_manager.session_protection = "strong"
        login_manager.login_view = 'login'
        login_manager.login_message = 'このページにアクセスするにはログインが必要です。'        
        
        # DynamoDBテーブルの初期化
        init_tables()
        logger.info("Application initialized successfully")
        
        return app
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

app = create_app()  # アプリケーションの初期化

def tokyo_time():
    return datetime.now(pytz.timezone('Asia/Tokyo'))

@login_manager.user_loader
def load_user(user_id):
    app.logger.debug(f"Loading user with ID: {user_id}")
    
    if not user_id:
        app.logger.warning("No user_id provided to load_user")
        return None

    try:
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={'user_id': {'S': user_id}}
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
        

       

from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash





def get_user_from_dynamodb(user_id):
    try:
        # DynamoDBからユーザーデータを取得
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={"user_id": {"S": user_id}}
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

    return render_template("index.html", form=form, schedules=schedules)


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
                    "user_id": {"S": user_id},
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
                    "user_name": {"S": form.user_name.data}
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

    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # form = LoginForm(dynamodb_table=app.table)
    form = LoginForm()
    if form.validate_on_submit():
        try:
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
                    user_id=user_data['user_id'],
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
    
    return render_template('edit_schedule.html', form=form, schedule_id=schedule_id)


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
# @login_required
def user_maintenance():
    try:
        # テーブルからすべてのユーザーを取得
        response = app.table.scan()
        
        # デバッグ用に取得したユーザーデータを表示
        users = response.get('Items', [])
        app.logger.info(f"Retrieved {len(users)} users for maintenance page")

        return render_template(
            "user_maintenance.html",
            users=users,
            page=1,
            has_next=False
        )

    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('ユーザー情報の取得に失敗しました。', 'error')
        return redirect(url_for('index'))


@app.route('/<string:user_id>/account', methods=['GET', 'POST'])  # UUIDは文字列なのでintからstringに変更
# @login_required
def account(user_id):
    # DynamoDBからユーザー情報を取得
    try:
        response = app.dynamodb.get_item(
            TableName=app.table_name,
            Key={
                'user_id': {'S': user_id}
            }
        )
        user = response.get('Item')
        if not user:
            abort(404)
            
        # 現在のユーザーが対象ユーザーまたは管理者であることを確認
        if user['user_id']['S'] != current_user.get_id() and not current_user.is_administrator:
            abort(403)

        form = UpdateUserForm(user_id)
        
        if form.validate_on_submit():
            current_time = datetime.now().isoformat()
            
            # パスワードが入力された場合はハッシュ化
            update_expression_parts = []
            expression_values = {}
            
            # 更新する項目を設定
            if form.user_name.data:
                update_expression_parts.append("user_name = :user_name")
                expression_values[':user_name'] = {'S': form.user_name.data}
                
            if form.email.data:
                update_expression_parts.append("email = :email")
                expression_values[':email'] = {'S': form.email.data}
                
            if form.password.data:
                hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
                update_expression_parts.append("password = :password")
                expression_values[':password'] = {'S': hashed_password}

            # 更新日時は常に更新
            update_expression_parts.append("updated_at = :updated_at")
            expression_values[':updated_at'] = {'S': current_time}

            # DynamoDBを更新
            response = app.dynamodb.update_item(
                TableName=app.table_name,
                Key={
                    'user_id': {'S': user_id}
                },
                UpdateExpression="SET " + ", ".join(update_expression_parts),
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW"
            )
            
            flash('ユーザーアカウントが更新されました', 'success')
            return redirect(url_for('user_maintenance'))
            
        elif request.method == 'GET':
            # フォームに現在の値を設定
            form.user_name.data = user.get('user_name', {}).get('S', '')
            form.email.data = user.get('email', {}).get('S', '')
            
        return render_template('account.html', form=form)
        
    except ClientError as e:
        app.logger.error(f"DynamoDB error: {str(e)}")
        flash('データベースエラーが発生しました。', 'error')
        return redirect(url_for('user_maintenance'))   

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
    
@app.route("/remove_user_id")
def remove_user_id():
    try:
        table = get_schedule_table()
        response = table.scan()
        items = response['Items']
        
        success_count = 0
        error_count = 0
        
        for item in items:
            try:
                # 両方のキーを指定
                table.update_item(
                    Key={
                        'venue_date': item['venue_date'],
                        'schedule_id': item['schedule_id']
                    },
                    UpdateExpression='REMOVE user_id, #s',  # status も同時に削除
                    ExpressionAttributeNames={
                        '#s': 'status'
                    }
                )
                success_count += 1
                print(f"Processed: {item['venue_date']} - {item['schedule_id']}")
            except Exception as e:
                print(f"Error with item {item['schedule_id']}: {str(e)}")
                error_count += 1
                continue
        
        return f'Processed {success_count + error_count} items. Success: {success_count}, Errors: {error_count}'
    except Exception as e:
        return f'Error: {str(e)}'
    

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')
    
@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        title = request.form.get("title")
        body = request.form.get("body")
        image = request.files.get("image")
        

        
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

         # デバッグ用に結果を出力
        print(f"Title: {title}")
        print(f"Body: {body}")
        print(f"Image URL: {image_url}")

        # new_post = Post(title=title, body=body, image_url=image_url, category_id=category_id)
        # db.session.add(new_post)
        # db.session.commit()

        # 投稿完了後トップページにリダイレクト
        return redirect(url_for('index'))
    



    # GET メソッドでフォームを表示
    return render_template("create.html")


                          

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