from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.contrib.auth import login as auth_login
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login
from rest_framework_simplejwt.tokens import RefreshToken
from botocore.client import Config
from django.http import HttpResponse


import boto3
import uuid
import io
import qrcode
import qrcode.image.pil
from base64 import b64encode

from .forms import LoginForm, FileUploadForm, RegisterForm
from .models import File, Folder
from .utils import log_file_action

# ---------- MFA SETUP ----------
@login_required
def mfa_setup(request):
    """
    A view to set up MFA for the user. It generates a QR code
    for the user to scan with their TOTP app. The QR code is
    generated using the TOTPDevice model from django_otp.
    """	
    user = request.user
    device, created = TOTPDevice.objects.get_or_create(user=user, name='default', confirmed=False)

    if not device.confirmed:
        otp_uri = device.config_url
        factory = qrcode.image.pil.PilImage
        img = qrcode.make(otp_uri, image_factory=factory)

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_image_base64 = b64encode(buffer.getvalue()).decode()

        return render(request, 'storage/mfa_setup.html', {'qr_code_base64': qr_image_base64})

    return redirect('profile')

@login_required
def reset_mfa_device(request):
    """	
    A view to reset the MFA device for the user. It deletes
    the existing TOTPDevice and allows the user to re-enroll.
    This is useful if the user has lost access to their TOTP
    app or needs to reset their MFA settings.
    """
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        request.user.is_mfa_enabled = False
        request.user.save()
        messages.success(request, "MFA device reset. You can now re-enroll.")
        return redirect('mfa_setup')

    return render(request, 'storage/reset_mfa.html')

@login_required
def disable_mfa(request):
    """	
    A view to disable MFA for the user. It deletes the
    existing TOTPDevice and updates the user's MFA status.
    This is useful if the user no longer wants to use MFA
    or needs to disable it for any reason.
    """	
    if request.method == 'POST':
        devices = TOTPDevice.objects.filter(user=request.user, confirmed=True)
        devices.delete()
        request.user.is_mfa_enabled = False
        request.user.save()
        messages.success(request, "MFA has been disabled.")
        return redirect('profile')
    return render(request, 'storage/disable_mfa.html')

@login_required
def mfa_verify(request):
    """
    A view to verify the MFA token entered by the user.
    It checks the token against the TOTPDevice and logs in
    the user if the token is valid. This is used during
    the login process to ensure that the user has access
    to their MFA device.
    """
    if request.method == "POST":
        token = request.POST.get("token")
        device = TOTPDevice.objects.filter(user=request.user, name='default').first()

        if device and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save()
            otp_login(request, device)
            request.user.is_mfa_enabled = True
            request.user.save()
            messages.success(request, "MFA verification successful.")
            return redirect('profile')
        else:
            messages.error(request, "Invalid token. Try again.")
    return render(request, 'storage/mfa_verify.html')

# ---------- USER AUTH ----------
def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            return redirect('dashboard')
    else:
        form = RegisterForm()
    return render(request, 'storage/register.html', {'form': form})

def user_login(request):
    """
    A view to handle user login. It uses the built-in
    AuthenticationForm from Django to authenticate the user.
    If the user is authenticated, it logs them in and
    redirects them to the dashboard. If the user is not
    authenticated, it shows an error message.
    """ 
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            refresh = RefreshToken.for_user(user)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")
    else:
        form = LoginForm()
    return render(request, 'storage/login.html', {'form': form})

def user_logout(request):
    """
    A view to handle user logout. It clears the session
    and logs the user out. It also deletes the access
    and refresh tokens from the session. After logging out,
    it redirects the user to the login page.
    """
    request.session.pop('access_token', None)
    request.session.pop('refresh_token', None)
    logout(request)
    return redirect('login')

# ---------- PROFILE & DASHBOARD ----------
@login_required
def profile(request):
    """
    A view to display the user's profile. It shows the
    user's MFA status and a list of files uploaded by
    the user. The profile page also allows the user to
    manage their MFA settings and view their uploaded files.
    """
    mfa_status = "Enabled" if request.user.is_mfa_enabled else "Disabled"
    files = File.objects.filter(uploaded_by=request.user)
    return render(request, 'storage/profile.html', {'mfa_status': mfa_status, 'files': files})

@login_required
def dashboard(request):
    """
    A view to display the user's dashboard. It shows a
    list of files that the user has uploaded, shared with
    them, or that are public. The dashboard allows the user
    to manage their files, upload new files, and access
    their shared files. The dashboard is the main interface
    for the user to interact with the file storage system.
    """
    user = request.user
    files = File.objects.filter(
        Q(uploaded_by=user) | Q(shared_with=user) | Q(is_public=True)
    ).distinct()
    return render(request, 'storage/dashboard.html', {'files': files})

# ---------- FILE HANDLING ----------
def upload_to_s3(file, s3_key):
    """
    Uploads a file to S3 using the provided S3 key.
    The file is uploaded to the S3 bucket specified in
    the settings. The S3 key is a unique identifier for
    the file in the S3 bucket. The function uses the
    boto3 library to interact with the S3 service.
    """
    s3 = boto3.client('s3')
    s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, s3_key)
    return s3_key

@login_required
def upload_file(request):
    """
    A view to handle file uploads. It uses the FileUploadForm
    to validate the file and its metadata. If the form is
    valid, it uploads the file to S3 and creates a File
    instance in the database. The file is associated with
    the user who uploaded it. The view also allows the user
    to specify a folder for the file, share it with other
    users, and set its visibility (public or private).
    """
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_obj = request.FILES['file_obj']
            file_name = form.cleaned_data['file_name']
            folder = form.cleaned_data.get('folder')
            shared_with = form.cleaned_data.get('shared_with')
            is_public = form.cleaned_data.get('is_public')

            s3_key = f"{request.user.id}/{folder.name if folder else 'root'}/{uuid.uuid4()}_{file_obj.name}"
            upload_to_s3(file_obj, s3_key)

            file_instance = File.objects.create(
                file_name=file_name,
                s3_key=s3_key,
                uploaded_by=request.user,
                folder=folder,
                is_public=is_public,
            )

            if shared_with:
                file_instance.shared_with.set(shared_with)
            # ✅ Log upload action
            log_file_action(request.user, file_instance, 'UPLOAD', request)

            messages.success(request, "File uploaded successfully.")
            return redirect('upload_file')
    else:
        form = FileUploadForm()
    return render(request, 'storage/upload_file.html', {'form': form})

# ---------- SECURE ACTIONS (OTP-Protected Delete & Download) ----------
def generate_presigned_url(s3_key, expiration=300):
    """
    Generates a presigned URL for downloading a file from S3.
    The URL is valid for a specified duration (default is
    5 minutes). The presigned URL allows the user to download
    the file without needing to authenticate with AWS. The
    function uses the boto3 library to generate the URL.
    """
    s3 = boto3.client(
        's3',
        region_name='us-east-1',
        config=Config(signature_version='s3v4')
    )

    return s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': s3_key},
        ExpiresIn=expiration
    )

@login_required
def verify_action_otp(request, file_id, action):
    """
    A view to verify the OTP for secure file actions (download/delete).
    It checks the OTP entered by the user against the TOTPDevice
    associated with the user. If the OTP is valid, it allows
    the user to proceed with the action (download/delete). If
    the OTP is invalid, it shows an error message. The view
    also logs the action (successful or failed) for auditing
    purposes.
    """
    file = get_object_or_404(File, id=file_id, uploaded_by=request.user)

    if request.method == "POST":
        token = request.POST.get("token")
        device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()

        if device and device.verify_token(token):
            request.session['verified_file_action'] = f"{file_id}:{action}"
            request.session.set_expiry(300)
            return redirect('secure_file_action', file_id=file.id, action=action)
        else:
            log_file_action(request.user, file, f'{action.upper()}_FAILED_OTP', request)
            messages.error(request, "Invalid OTP code")

    return render(request, 'storage/verify_action_otp.html', {'file': file, 'action': action})

@login_required
def secure_file_action(request, file_id, action):
    """
    A view to handle secure file actions (download/delete).
    It checks if the user has verified the action using
    OTP. If the action is verified, it proceeds with the
    action (download/delete). The view also logs the action
    (successful or failed) for auditing purposes. The
    download action generates a presigned URL for the file
    in S3, allowing the user to download the file securely.
    The delete action removes the file from S3 and deletes
    the file instance from the database. The view also
    handles the case where the user has not verified the
    action, redirecting them to the OTP verification page.
    """
    file = get_object_or_404(File, id=file_id, uploaded_by=request.user)
    expected = f"{file_id}:{action}"

    if request.session.get('verified_file_action') != expected:
        return redirect('verify_action_otp', file_id=file.id, action=action)

    if action == 'download':
        url = generate_presigned_url(file.s3_key)
        # ✅ Log download action
        log_file_action(request.user, file, 'DOWNLOAD', request)
        return redirect(url)

    elif action == 'delete':
        s3 = boto3.client('s3')
        s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=file.s3_key)
        # ✅ Log download action
        log_file_action(request.user, file, 'DELETE', request)

        file.delete()
        messages.success(request, f"{file.file_name} deleted successfully.")
        return redirect('dashboard')

    return HttpResponse("Invalid action.", status=400)
