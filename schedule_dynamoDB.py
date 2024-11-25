from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError

# .envファイルから環境変数を読み込む
load_dotenv()

# AWS認証情報を辞書として定義
aws_credentials = {
    'aws_access_key_id': os.getenv("AWS_ACCESS_KEY_ID"),
    'aws_secret_access_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
    'region_name': os.getenv("AWS_REGION")
}

def create_schedule_table():
    try:
        # 認証情報を使用してDynamoDBリソースを作成
        dynamodb = boto3.resource('dynamodb', **aws_credentials)
        
        # テーブルが既に存在するか確認
        existing_tables = list(dynamodb.tables.all())
        if any(table.name == 'Schedule' for table in existing_tables):
            print("テーブルは既に存在します")
            return dynamodb.Table('Schedule')
        
        # テーブルの作成
        table = dynamodb.create_table(
            TableName='Schedule',
            KeySchema=[
                {
                    'AttributeName': 'venue_date',
                    'KeyType': 'HASH'  # パーテーションキー
                },
                {
                    'AttributeName': 'schedule_id',
                    'KeyType': 'RANGE'  # ソートキー
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'venue_date',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'schedule_id',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        
        # テーブルが作成されるまで待機
        print("テーブルを作成中...")
        table.meta.client.get_waiter('table_exists').wait(TableName='Schedule')
        print("テーブルが正常に作成されました")
        return table
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print("テーブルは既に存在します")
            return dynamodb.Table('Schedule')
        else:
            print(f"エラーが発生しました: {str(e)}")
            return None
    except Exception as e:
        print(f"予期せぬエラーが発生しました: {str(e)}")
        return None

def verify_credentials():
    """AWS認証情報の検証"""
    try:
        dynamodb = boto3.resource('dynamodb', **aws_credentials)
        # 既存のテーブル一覧を取得してみる（認証テスト）
        list(dynamodb.tables.all())
        print("AWS認証情報は有効です")
        return True
    except Exception as e:
        print(f"AWS認証情報の検証に失敗しました: {str(e)}")
        return False

if __name__ == '__main__':
    if verify_credentials():
        table = create_schedule_table()
        if table:
            print(f"テーブル状態: {table.table_status}")
    else:
        print("AWS認証情報を確認してください")