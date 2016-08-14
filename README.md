# fsnd-item-catalog
Item Catalog
Installing the Vagrant VM
You will use a virtual machine (VM) for all of the activities in this course. 
The VM is a Linux server system that runs on top of your own computer.

VirtualBox

VirtualBox is the software that actually runs the VM. You can download it from virtualbox.org, here
Install the platform package for your operating system.  You do not need the extension pack or the SDK.

Vagrant

Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. 
You can download it from vagrantup.com. Install the version for your operating system.

Run the virtual machine!

Using the terminal, change directory to fullstack/vagrant (cd fullstack/vagrant), then type vagrant up to launch your virtual machine.
Once it is up and running, type vagrant ssh to log into it.
This will log your terminal in to the virtual machine, and you'll get a Linux shell prompt.
When you want to log out, type exit at the shell prompt.
To turn the virtual machine off (without deleting anything), type vagrant halt.
If you do this, you'll need to run vagrant up again before you can log into it.
Be sure to change to the /vagrant directory by typing cd /vagrant in order to share files between your home machine and the VM. 

