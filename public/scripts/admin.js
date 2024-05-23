const listOfUsers = document.querySelector('.listOfUsers');

window.addEventListener('load', () =>{
    showAll();
})


function generateUserBlock(user) {
    console.log(user);
    const userBlock = document.createElement("tr");
    userBlock.classList.add("users");

    const username = user.username + "Username";
    const email = user.email + "Email";
    const password = user.password + "Password";

    userBlock.innerHTML = `
        <td><input type="text" class="form-control" id="${username}" value="${user.username}"></td>
        <td><input type="text" class="form-control" readonly id="${email}" value="${user.email}"></td>
        <td><input type="text" class="form-control" readonly id="${password}${email}" value="${user.password}"></td>
        <td>
            <button class="btn loginButton text-white px-4" style="background-color: rgb(13, 133, 253);"
            onclick="saveUser('${username}', '${email}', '${password}${email}')">Save</button>
            <button class="btn btn-danger px-4" onclick="deleteUser('${user.email}')">Delete</button>
        </td>
    `;

    listOfUsers.appendChild(userBlock);
}


async function showAll() {
    try {
        const users = await getUsers();
        users.forEach(function(user){
            generateUserBlock(user);
        });
    } catch (error) {
        console.error('Error fetching and displaying users:', error);
    }
}

function clearAll() {
    const users = document.querySelectorAll(".users");

    users.forEach(user => {
        user.remove();
    })
}

async function saveUser(usernameInputId, emailInputId, passwordInputId) {
    try {
        const username = document.getElementById(usernameInputId).value;
        const email = document.getElementById(emailInputId).value;
        const password = document.getElementById(passwordInputId).value;

        const userData = {
            username: username,
            email: email,
            password: password
        };

        const response = await fetch('/admin/updateUser', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Server response:', data);
        clearAll();
        showAll();
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

async function deleteUser(userEmail) {
    try {
        const response = await fetch(`/admin/deleteUser/${encodeURIComponent(userEmail)}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();
        console.log('User deletion successful:', data);
        clearAll();
        showAll();
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

async function search() {
    clearAll();

    const email = document.getElementById('userEmail').value;

    if (email === "") {
        showAll();
    } else {
        try {
            const user = await getUserByEmail(email);

            if (user) {
                generateUserBlock(user);
            } else {
                console.log(`User with e-mail ${email} not found.`);
            }
        } catch (error) {
            console.error('Error fetching user by e-mail:', error);
        }
    }
}

async function sendNewsletter() {
    const message = document.getElementById('newsletterMessage').value;

    try {
        const response = await fetch('/admin/newsletter', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: message,
            })
        });
        
        if (!response.ok) {
            const jsonReponse = await response.json()
            throw new Error(jsonReponse.message);
        }
        console.log(response)
        const myModal = document.getElementById('newsletterModal');
        $(myModal).modal('hide');
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

async function createUser() {
    const newUsername = document.getElementById('newUsername').value;
    const newEmail = document.getElementById('newEmail').value;
    const newPassword = document.getElementById('newPassword').value;

    try {
        const response = await fetch('/admin/addUser', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: newUsername,
                email: newEmail,
                password: newPassword
            })
        });
        
        if (!response.ok) {
            const jsonReponse = await response.json()
            throw new Error(jsonReponse.message);
        }

        const data = await response.json();
        console.log('User added successfully:', data);

        const myModal = document.getElementById('createModal');
        $(myModal).modal('hide');
        clearAll();
        showAll();
    } catch (error) {
        console.error('Fetch error:', error);
    }
}

async function getUsers() {
    try {
        const response = await fetch('/admin/getAllUsers');
        console.log(response)
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const responseData = await response.json();
        const users = responseData.data
        return users;
    } catch (error) {
        console.error('Error fetching users:', error);
        throw new Error('Unable to fetch users');
    }
}

async function getUserByEmail(email) {
    try {
        const response = await fetch(`/admin/getUser/${email}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const user = responseData.data
        return user;
    } catch (error) {
        console.error(`Error fetching user with email ${email}:`, error);
        throw new Error(`Unable to fetch user with email ${email}`);
    }
}

async function loadAdminPanelChats() {
    try {
        const response = await fetch('/admin/chats');
        if (!response.ok) {
            throw new Error('Failed to fetch chats');
        }
        const chats = await response.json();

        const chatModal = document.getElementById('chatModal');
        const modalBody = chatModal.querySelector('.modal-body');

        modalBody.innerHTML = "";

        if (chats.length === 0) {
            modalBody.textContent = "No available chats.";
        } else {
            chats.forEach(chat => {
                const chatElement = document.createElement('div');
                chatElement.className = "chat-item row mb-2 align-items-center";
                chatElement.innerHTML = `
                    <div class = "col-10">Chat ID: ${chat.id}</div>
                    <div class = "col-2 text-end">
                    <button class="btn btn-primary px-4" onclick="joinChat('${chat.id}')">Join</button>
                    </div>
                `;
                modalBody.appendChild(chatElement);
            });
        }
    } catch (error) {
        console.error('Fetch error:', error);
        const chatModal = document.getElementById('chatModal');
        const modalBody = chatModal.querySelector('.modal-body');
        modalBody.textContent = "Failed to load chats.";
    }
}

function joinChat(chatId) {
    console.log(`Joining chat ${chatId}`);
    window.location.href = `admin/chats/${chatId}`;
}

let chatInterval;

// Обработчики событий открытия и закрытия модального окна
document.getElementById('chatModal').addEventListener('show.bs.modal', function () {
    loadAdminPanelChats(); // Загрузка чатов сразу при открытии модального окна
    chatInterval = setInterval(loadAdminPanelChats, 5000); // Запуск интервала обновления каждые 5 секунд
});

document.getElementById('chatModal').addEventListener('hide.bs.modal', function () {
    clearInterval(chatInterval); // Остановка интервала при закрытии модального окна
});