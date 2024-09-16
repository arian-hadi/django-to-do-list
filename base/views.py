from django import forms
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView,UpdateView,DeleteView,FormView
from .models import Task
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import login, get_user_model, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User



class CustomAuthenticationForm(forms.Form):
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(CustomAuthenticationForm, self).__init__(*args, **kwargs)

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        if email and password:
                self.user_cache = authenticate(self.request, email = email, password = password)
                if self.user_cache is None:
                    raise forms.ValidationError('Invalid password or email')
            
        return self.cleaned_data
        
    def get_user(self):
        return self.user_cache



class CustomLoginView(LoginView):
    template_name = 'base/login.html'
    authentication_form = CustomAuthenticationForm 
    redirect_authenticated_user = True

    def get_form_kwargs(self):
        kwargs = super(CustomLoginView, self).get_form_kwargs()
        kwargs['request'] = self.request  # Pass the request to the form
        return kwargs


    def get_success_url(self):
        return reverse_lazy('tasks')

    
class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']


class Register(FormView):
    template_name = 'base/register.html'
    #form_class = UserCreationForm
    form_class = RegisterForm
    success_url = reverse_lazy('tasks')

    def form_valid(self, form):
        user = form.save() #save the user
        if user is not None:
            login(self.request, user) #log the user in
        return super(Register,self).form_valid(form)

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('tasks')
        return super(Register, self).get(*args, **kwargs)


class TaskList(LoginRequiredMixin, ListView):
    model = Task
    context_object_name = 'tasks'
    template_name = 'base/task.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['tasks'] = context['tasks'].filter(user = self.request.user)
        context['count'] = context['tasks'].filter(complete = False).count()

        search_input = self.request.GET.get('search-task') or ''
        if search_input:
            context['tasks'] = context['tasks'].filter(title__startswith = search_input)
        context['search_input'] = search_input
        return context

class TaskDetail(LoginRequiredMixin, DetailView):
    model = Task
    context_object_name = 'task'

class TaskCreate(LoginRequiredMixin, CreateView):
    model = Task
    fields = ['title', 'description', 'complete']
    success_url = reverse_lazy('tasks')

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super(TaskCreate,self).form_valid(form)

class TaskUpdate(LoginRequiredMixin, UpdateView):
    model = Task
    fields = ['title', 'description', 'complete']
    success_url = reverse_lazy('tasks')

class TaskDelete(LoginRequiredMixin, DeleteView):
    model = Task
    context_object_name = 'task'
    success_url = reverse_lazy('tasks')