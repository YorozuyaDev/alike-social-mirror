#Confirmation Request

confirmation_text = """\
Hello {username},
Welcome to Alike Social, please click the link below
to complete your registration and start sharing.
{confirmation_url}
If it wasn't you just ignore this email.
"""

confirmation_html = """\
    <html>
    <head>
    <style>
    #text {{color: blue;}} 
    </style>
    </head>
    <body>
    <h3>Hello {username},</h3>
    <p id='text'>
    Welcome to Alike Social, please click the link below
    to complete your registration and start sharing.
    </p>
    <a href='{confirmation_url}'>Activate your account</a>
    <p>If it wasn't you just ignore this email.</p>
    </body>
    </html>
    """  

#Email Request

change_password_text = """\
Hello,
Forgot your password?
We received a request to reset the password for your account.
To reset your password click here:
{change_password_url}
If it wasn't you just ignore this email.
"""

change_password_html = """\
    <html>
    <head>
    <style>
    #text {{color: blue;}} 
    </style>
    </head>
    <body>
    <h3>Hello,</h3>
    <p id='text'>
    We received a request to reset the password for your account.
    To reset your password click here:
    </p>
    <a href='{change_password_url}'> Recover your password </a>
    <p>If it wasn't you just ignore this email.</p>
    </body>
    </html>
    """  
