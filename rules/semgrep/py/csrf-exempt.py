from django.views.decorators.csrf import csrf_exempt


# ruleid: newsoc.py.csrf-exempt
@csrf_exempt
def a(request):
    return None


# ruleid: newsoc.py.csrf-exempt
@csrf_exempt
def b(request, pk):
    return None


# ruleid: newsoc.py.csrf-exempt
@csrf_exempt
def c(request):
    pass


# ok: newsoc.py.csrf-exempt
def ok1(request):
    return None


# ok: newsoc.py.csrf-exempt
@login_required
def ok2(request):
    return None


# ok: newsoc.py.csrf-exempt
@csrf_protect
def ok3(request):
    return None
