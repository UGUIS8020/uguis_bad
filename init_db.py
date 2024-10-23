from app import db, Category, app

with app.app_context():
    db.create_all()

        # 既存のデータをすべて削除
    db.session.query(Category).delete()
    db.session.commit()

    category_names = [
        "歯科技工",
        "バドミントン",
        "旅行",
        "車",
        "占い",
        "料理",
        "グルメ",
        "映画",
        "音楽",
        "ビジネス",
        "その他"
    ]

    for name in category_names:
        category = Category.query.filter_by(name=name).first()
        if category:
            # 既存カテゴリを更新（必要に応じて他のフィールドも更新可能）
            category.name = name  # 名前以外のフィールドを更新するならここで行う
        else:
            # 新しいカテゴリを作成
            category = Category(name=name)
            db.session.add(category)

    db.session.commit()