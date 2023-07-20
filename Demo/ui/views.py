from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader

from .forms import LoginForm, HomepageForm

import EnclaveConnection
# Create your views here.

# def login(request):
#     template = loader.get_template('loginPage.html')
#     return HttpResponse(template.render())
userName = ""

def loginAction(request):
    qrCode = None
    # if this is a POST request we need to process the form data
    if request.method == "POST":
        # create a form instance and populate it with data from the request:
        form = LoginForm(request.POST)
        # check whether it's valid:
        # if form.is_valid():
        #     # process the data in form.cleaned_data as required
        EnclaveConnection.sendInput("OK")
        #     global userName
        #     userName = form.cleaned_data['userName']
        #     # print(form.cleaned_data["userName"])
        #     # ...
            # redirect to a new URL:
        return HttpResponseRedirect("/home/main/")

    # if a GET (or any other method) we'll create a blank form
    else:
        EnclaveConnection.connectToEnclave()
        form = LoginForm() 
        qrCode = EnclaveConnection.createQRCode(EnclaveConnection.lastMessage)
        # print(qrCode)

    return render(request, "loginPage.html", {"form": form, "qrCode": qrCode})

def homePage(request):

    if request.method == "POST":
         # create a form instance and populate it with data from the request:
        form = HomepageForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            # process the data in form.cleaned_data as required
            EnclaveConnection.sendInput(form.cleaned_data['userInput'])
            # global userName
            # userName = form.cleaned_data['userName']
            # print(form.cleaned_data["userName"])
            # ...
            # redirect to a new URL:
            # return HttpResponseRedirect("/home/welcome/")
            qrCode = EnclaveConnection.createQRCode(EnclaveConnection.receiveResponse())
            # qrCode = EnclaveConnection.createQRCode(EnclaveConnection.lastMessage)
            # print(qrCode)

            # New blank form
            form = HomepageForm() 
            return render(request, "homePage.html", {"userName": userName, "form": form, "qrCode": qrCode})

        
    else:
        # EnclaveConnection.connectToEnclave()
        form = HomepageForm() 
        qrCode = EnclaveConnection.createQRCode(EnclaveConnection.receiveResponse())
        # qrCode = EnclaveConnection.createQRCode(EnclaveConnection.lastMessage)
        # print(qrCode)

        return render(request, "homePage.html", {"userName": userName, "form": form, "qrCode": qrCode})
