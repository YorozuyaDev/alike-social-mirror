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
