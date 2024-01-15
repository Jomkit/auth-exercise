from models import User, Feedback, connect_db, db
from app import app

# Drop and create all tables to start clean
db.drop_all()
db.create_all()

# Make sure user table is empty
User.query.delete()

admin = User.register(username='testAdmin', 
                    password='123test123', 
                    email="admin@gmail.com", 
                    first_name="Test", 
                    last_name="Admin")
admin.is_admin = True

jim = User.register(username='yesMan', 
                    password='alrightythen', 
                    email="jimborini@gmail.com", 
                    first_name="Jim", 
                    last_name="Carrey")

patty = User.register(username='PattyBanany', 
                    password='patrickstar', 
                    email="patban@gmail.com", 
                    first_name="Patricia", 
                    last_name="Banadam")

john = User.register(username='mrTravolta', 
                    password='footloose', 
                    email="travolta@gmail.com", 
                    first_name="John", 
                    last_name="Travolta")

steve = User.register(username='crocGuy', 
                    password='stingraysAreCool', 
                    email="crikeysheila@gmail.com", 
                    first_name="Steve", 
                    last_name="Irwin")

mc = User.register(username='titanicSinger', 
                    password='christmasSucks', 
                    email="heartgoeson@gmail.com", 
                    first_name="Mariah", 
                    last_name="Carey")

db.session.add_all([admin, jim, patty, john, steve, mc])

########## FEEDBACK INSTANCES ##############
all_feedback = [
Feedback(title='test',content="I'm testing admin stuff", username="testAdmin"),
Feedback(title='not Patrick from Spongebob',content="This isn't actually a spongebob reference", username="PattyBanany"),
Feedback(title='yikes',content="I just saw a cougar", username="PattyBanany"),
Feedback(title='movies',content="I was in hairspray", username="mrTravolta"),
Feedback(title='movies2',content="I was in Grease", username="mrTravolta"),
Feedback(title='movies3',content="I was in Pulp Fiction", username="mrTravolta"),
Feedback(title='movies4',content="I was in Saturday Night Fever", username="mrTravolta"),
Feedback(title='movies5',content="I was in Face/Off. Nicholas Cage is cool", username="mrTravolta"),
Feedback(title='sick of this',content="Wish people would think of titanic more than christmas music when they think of me", username="titanicSinger"),
Feedback(title='test',content="I'm too lazy to keep typing new stuff", username="yesMan"),
Feedback(title='wow',content="I'm Jim Carrey", username="yesMan"),
Feedback(title='actor Extraordinary',content="I'm so funny and handsome and loved", username="yesMan")

]

db.session.add_all(all_feedback)

db.session.commit()