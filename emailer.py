import os

import jinja2
import sendgrid
from sendgrid.helpers.mail import Content
from sendgrid.helpers.mail import Email
from sendgrid.helpers.mail import Mail
from sendgrid.helpers.mail import Personalization
from sendgrid.helpers.mail import To

from app import logger


def create_email(address, subject, template_name, template_data):
    template_loader = jinja2.FileSystemLoader(searchpath='templates')
    template_env = jinja2.Environment(loader=template_loader)
    html_template = template_env.get_template(template_name + '.html')

    html_to_send = html_template.render(template_data)
    content = Content('text/html', html_to_send)

    support_email = Email('team@ourresearch.org', 'OpenAlex Team')
    to_email = To(address)

    email = Mail(support_email, to_email, subject, content)
    personalization = Personalization()
    personalization.add_to(to_email)
    email.add_personalization(personalization)

    logger.info('sending email "{}" to {}'.format(subject, address))

    return email


def send(email, for_real=False):
    if for_real:
        sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
        email_get = email.get()
        sg.client.mail.send.post(request_body=email_get)
        print("Sent an email")
    else:
        print("Didn't really send")