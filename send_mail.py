import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from os import environ

SENDER_EMAIL = environ['SENDER_EMAIL_ADDRESS']
SENDER_PASS = environ['SENDER_EMAIL_PASSWORD']


def send_confirmation_mail(recipient, link):
    try:
        mail_content = '''Please click the link below to confirm your email: {}'''.format(link)

        # Setup the MIME
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = recipient
        message['Subject'] = 'UPM-Chat Email confirmation'  # The subject line

        # The body and the attachments for the mail
        message.attach(MIMEText(mail_content, 'plain'))
        # Create SMTP session for sending the mail

        session = smtplib.SMTP('smtp.gmail.com', 587)  # use gmail with port
        session.starttls()  # enable security
        session.login(SENDER_EMAIL, SENDER_PASS)  # login with mail_id and password
        text = message.as_string()
        session.sendmail(SENDER_EMAIL, recipient, text)
        session.quit()
        return True
    except Exception as e:
        print('\n\n--------------------------------------------------------\n\n'
              + str(e) + '\n\n--------------------------------------------------------\n\n')
        return False


def send_reset_mail(recipient, link):
    try:
        mail_content = '''Please click the link below to reset your password: {}'''.format(link)

        # Setup the MIME
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = recipient
        message['Subject'] = 'UPM-Chat Password Reset'  # The subject line

        # The body and the attachments for the mail
        message.attach(MIMEText(mail_content, 'plain'))
        # Create SMTP session for sending the mail

        session = smtplib.SMTP('smtp.gmail.com', 587)  # use gmail with port
        session.starttls()  # enable security
        session.login(SENDER_EMAIL, SENDER_PASS)  # login with mail_id and password
        text = message.as_string()
        session.sendmail(SENDER_EMAIL, recipient, text)
        session.quit()
        return True
    except Exception as e:
        print('\n\n--------------------------------------------------------\n\n'
              + str(e) + '\n\n--------------------------------------------------------\n\n')
        return False
