import jwt
from flask import request, redirect, flash, url_for, session
from flask_appbuilder.security.manager import AUTH_DB
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.views import AuthDBView
from flask_login import login_user, current_user
from celery.schedules import crontab
from superset.security import SupersetSecurityManager

###############
###   APP   ###
###############
APP_NAME = "Dusys - Superset"
APP_ICON="https://i.postimg.cc/9FHY1cCW/slym.png"

LANGUAGES = {
    "en": {"flag": "us", "name": "English"},
    "es": {"flag": "es", "name": "Spanish"},
    "it": {"flag": "it", "name": "Italian"},
    "fr": {"flag": "fr", "name": "French"},
    "zh": {"flag": "cn", "name": "Chinese"},
    "zh_TW": {"flag": "tw", "name": "Traditional Chinese"},
    "ja": {"flag": "jp", "name": "Japanese"},
    "de": {"flag": "de", "name": "German"},
    "pt": {"flag": "pt", "name": "Portuguese"},
    "pt_BR": {"flag": "br", "name": "Brazilian Portuguese"},
    "ru": {"flag": "ru", "name": "Russian"},
    "ko": {"flag": "kr", "name": "Korean"},
    "sk": {"flag": "sk", "name": "Slovak"},
    "sl": {"flag": "si", "name": "Slovenian"},
    "nl": {"flag": "nl", "name": "Dutch"},
    "uk": {"flag": "uk", "name": "Ukranian"},
}
BABEL_DEFAULT_LOCALE = "pt_BR"
#BABEL_DEFAULT_FOLDER = "/usr/projects/translations"

##################
###   CONFIG   ###
##################
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://superset_user:5X69kQp^9%k]@localhost/superset'

SECRET_KEY="n1C8zcuMud47nkVEQooCcFxd3/ObMIl9gET3G4CW0CPk5/Hvsi9TTueX"
SUPERSET_SECRET_KEY="n1C8zcuMud47nkVEQooCcFxd3/ObMIl9gET3G4CW0CPk5/Hvsi9TTueX"

AUTH_USER_REGISTRATION = True
AUTH_TYPE = AUTH_DB

FEATURE_FLAGS = {
    "ALERT_REPORTS": True,
    "ALLOW_IFRAME_EMBED": True,
    "EMBEDDED_SUPERSET": True,
    "ENABLE_EXPLORE_DRAG_AND_DROP": True,
    "DashboardCrossFilters": True,
    "DASHBOARD_RBAC": True, 
    'PRESTO_EXPAND_DATA': False,
    "ENABLE_BABEL_LOCALIZATION": True,
}

##################
###   FORMAT   ###
##################
D3_FORMAT = {
    "decimal": ",",       
    "thousands": ".",  
    "grouping": [3],
    "currency": ["R$", ""]
}

D3_TIME_FORMAT = {
    "dateTime": "%x, %X",
    "date": "%-d/%-m/%Y",
    "time": "%-H:%M:%S",
    "periods": ["AM", "PM"],
    "days": ["domingo", "segunda-feira", "terça-feira", "quarta-feira",
             "quinta-feira", "sexta-feira", "sábado"],
    "shortDays": ["dom", "seg", "ter", "qua", "qui", "sex", "sáb"],
    "months": ["janeiro", "fevereiro", "março", "abril",
               "maio", "junho", "julho", "agosto",
               "setembro", "outubro", "novembro", "dezembro"],
    "shortMonths": ["jan", "fev", "mar", "abr",
                    "mai", "jun", "jul", "ago",
                    "set", "out", "nov", "dez"]
}

CURRENCIES = ["USD", "EUR", "GBP", "INR", "MXN", "JPY", "CNY", "BRL"]

################
###   CORS   ###
################
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True

ENABLE_CORS = True  # Ativa CORS globalmente
TALISMAN_ENABLED = False
CORS_OPTIONS = {
    "supports_credentials": True,
    "allow_headers": ["*"],
    "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
    "origins": ["*"],  # Ou liste dom�nios espec�ficos: ["http://seu-app-laravel.com"]
}

HTTP_HEADERS = {"X-Frame-Options": "ALLOWALL"}
#WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/

##################
###   CELERY   ###
##################
from celery.schedules import crontab
from cachelib.redis import RedisCache

RESULTS_BACKEND = RedisCache(
    host='localhost', port=6379, key_prefix='superset_results'
)

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_IMPORTS = ('superset.sql_lab',)

# Example periodic task (optional)
CELERYBEAT_SCHEDULE = {
    'reports_schedule': {
        'task': 'superset.tasks.some_periodic_task',
        'schedule': crontab(minute=0, hour='*/1'),
    },
}

###################################
###   CUSTOM SECURITY MANAGER   ###
###################################
class CustomAuthDBView(AuthDBView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        jwt_token = request.args.get('jwt')
        if jwt_token:
            try:
                payload = jwt.decode(jwt_token, 'JvY3gMHOCDnleijfdGTrAbKXalys95QEEOM7u674dHLGW2Yk67zVI4I95orkVejp', algorithms=['HS256'])
                
                company_id = payload.get('company_id')
                username  = payload.get('username')
                email     = payload.get('email')
                first_name = payload.get('first_name', 'Dusys')
                last_name  = payload.get('last_name',  'Viewer')

                session['company_id'] = company_id
                user = self.appbuilder.sm.find_user(email=email)
                if not user:
                    user = self.appbuilder.sm.add_user(
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        role=self.appbuilder.sm.find_role('CompanyUser'),
                        password='teste123'
                    )
                
                res = login_user(user, remember=True)
                return redirect(url_for('TableModelView.list'))
            except jwt.ExpiredSignatureError:
                flash('Ocorreu um erro ao realizar o login autom�tico!', 'warning')
            except jwt.InvalidTokenError:
                flash('Ocorreu um erro ao realizar o login autom�tico!', 'warning')
            
        return super().login()


from collections import namedtuple
FilterRow = namedtuple("FilterRow", ["id", "group_key", "clause"])
class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def get_rls_filters(self, table):
        filters = super().get_rls_filters(table)
        company_id = session.get("company_id")

        if any(role.name == "CompanyUser" for role in self.get_user_roles(current_user)):
            if company_id and current_user.is_authenticated:
                new_filters = []
                for filter_row in filters:
                    filter_id = filter_row[0]
                    group_key = filter_row[1]
                    clause = filter_row[2]
                    
                    new_clause = clause.replace("{{ company_id }}", str(company_id))
                    new_filters.append(FilterRow(filter_id, group_key, new_clause))
                
                return new_filters
        return filters

CUSTOM_SECURITY_MANAGER = CustomSecurityManager
