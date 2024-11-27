from flask_wtf import FlaskForm
from wtforms import ValidationError, StringField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_login import UserMixin
from datetime import datetime
from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash, check_password_hash




class RegistrationForm(FlaskForm):
    organization = SelectField('所属', choices=[('uguis', 'おかめ'),('other', 'その他')], default='uguis', validators=[DataRequired(message='所属を選択してください')])
    display_name = StringField('表示ネーム LINE名など', validators=[DataRequired(message='表示名を入力してください'), Length(min=3, max=30, message='表示名は3文字以上30文字以下で入力してください')])
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
    submit = SubmitField('登録')

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
    organization = SelectField('所属', choices=[('uguis', 'おかめ'), ('other', 'その他')], validators=[DataRequired(message='所属を選択してください')])    
    display_name = StringField('表示ネーム LINE名など', validators=[DataRequired(), Length(min=3, max=30)])    
    user_name = StringField('ユーザー名', validators=[DataRequired()])    
    furigana = StringField('フリガナ',  validators=[DataRequired()])    
    phone = StringField('電話番号', validators=[DataRequired(), Length(min=10, max=15, message='正しい電話番号を入力してください')])    
    post_code = StringField('郵便番号', validators=[DataRequired(), Length(min=7, max=7, message='ハイフン無しで７桁で入力してください')])    
    address = StringField('住所', validators=[DataRequired(), Length(max=100, message='住所は100文字以内で入力してください')])    
    email = StringField('メールアドレス', validators=[DataRequired(), Email(message='正しいメールアドレスを入力してください')])    
    password = PasswordField('パスワード', validators=[Optional(),  # パスワード変更は任意
                                                  Length(min=8, message='パスワードは8文字以上で入力してください'),EqualTo('pass_confirm', message='パスワードが一致していません')])    
    pass_confirm = PasswordField('パスワード(確認)')    
    gender = SelectField('性別', choices=[('', '性別'), ('male', '男性'), ('female', '女性'), ('other', 'その他')], validators=[DataRequired()])    
    date_of_birth = DateField('生年月日', format='%Y-%m-%d', validators=[DataRequired()])    
    submit = SubmitField('更新')

    def __init__(self, user_id, dynamodb_table, *args, **kwargs):
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        self.id = user_id
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
                    if item['user_id'] != self.id:
                        raise ValidationError('このメールアドレスは既に使用されています。')
                        
        except ClientError as e:
            raise ValidationError('メールアドレスの確認中にエラーが発生しました。')
        

class User(UserMixin):
    def __init__(self, user_id, display_name, user_name, furigana, email, password_hash, 
                 gender, date_of_birth, post_code, address, phone, 
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
        self.organization = organization
        self.administrator = administrator
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or datetime.now().isoformat()

    def get_id(self):
        return str(self.user_id)

    @staticmethod
    def from_dynamodb_item(item):
        def get_value(field, field_type='S', default=None):
            return item.get(field, {}).get(field_type, default)

        return User(
            user_id=get_value('user_id'),
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
            organization=get_value('organization', default='uguis'),
            administrator=bool(get_value('administrator', 'BOOL', False)),
            created_at=get_value('created_at'),
            updated_at=get_value('updated_at')
        )

    def to_dynamodb_item(self):
        fields = ['user_id', 'organization', 'address', 'administrator', 'created_at', 
                  'display_name', 'email', 'furigana', 'gender', 'password', 
                  'phone', 'post_code', 'updated_at', 'user_name']
        item = {field: {"S": str(getattr(self, field))} for field in fields if getattr(self, field, None)}
        item['administrator'] = {"BOOL": self.administrator}
        if self.date_of_birth:
            item['date_of_birth'] = {"S": self.date_of_birth}
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
        ('越谷総合体育館 第1体育室', '越谷総合体育館 第1体育室'),
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