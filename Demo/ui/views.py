from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader

from .forms import LoginForm, HomepageForm

import EnclaveConnection

def loginAction(request):
    qrCode = None

    if request.method == "POST":
        EnclaveConnection.sendInput("OK")
        # redirect to a new URL:
        return HttpResponseRedirect("/home/main/")

    # if a GET (or any other method) we'll create a blank form
    else:
        EnclaveConnection.connectToEnclave()
        form = LoginForm() 
        qrCode = EnclaveConnection.createQRCode(EnclaveConnection.lastMessage)

    return render(request, "loginPage.html", {"form": form, "qrCode": qrCode})

def homePage(request):

    if request.method == "POST":
         # create a form instance and populate it with data from the request:
        form = HomepageForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            # process the data in form.cleaned_data as required
            EnclaveConnection.sendInput(form.cleaned_data['userInput'])

            qrCode = EnclaveConnection.createQRCode(EnclaveConnection.receiveResponse())

            # New blank form
            form = HomepageForm() 
            return render(request, "homePage.html", {"form": form, "qrCode": qrCode})

        
    else:
        form = HomepageForm() 
        qrCode = EnclaveConnection.createQRCode(EnclaveConnection.receiveResponse())

        return render(request, "homePage.html", {"form": form, "qrCode": qrCode})
