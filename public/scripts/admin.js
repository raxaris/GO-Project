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
        <td><input type="text" class="form-control" id="${email}" value="${user.email}"></td>
        <td><input type="text" class="form-control" id="${password}" value="${user.password}"></td>
        <td>
            <button class="btn loginButton text-white px-0 mb-1 me-3" style="background-color: rgb(13, 133, 253);"
            onclick="updateUser('${username}', '${email}', '${password}')">Save</button>
            <button class="btn btn-danger" onclick="deleteUser('${user.email}')">Delete</button>
        </td>
    `;

    listOfUsers.appendChild(userBlock);
}


async function showAll() {
    try {
        const usersData = await getUsers();
        users = usersData.data;
        console.log(users);
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

async function updateUser(usernameInputId, emailInputId, passwordInputId) {
    try {
        const username = document.getElementById(usernameInputId).value;
        const email = document.getElementById(emailInputId).value;
        const password = document.getElementById(passwordInputId).value;

        const userData = {
            username: username,
            email: email,
            password: password
        };
        console.log(userData)
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
        const response = await fetch(`/admin/deleteUser?email=${encodeURIComponent(userEmail)}`, {
            method: 'DELETE',
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

    const id = document.getElementById('userId').value;

    if (id === "") {
        showAll();
    } else {
        try {
            const user = await getUserById(id);

            if (user) {
                generateUserBlock(user);
            } else {
                console.log(`User with ID ${id} not found.`);
            }
        } catch (error) {
            console.error('Error fetching user by ID:', error);
        }
    }
}

async function getUsers() {
    try {
        const response = await fetch('/admin/getAllUsers');
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const users = await response.json();
        return users;
    } catch (error) {
        console.error('Error fetching users:', error);
        throw new Error('Unable to fetch users');
    }
}

async function getUserById(id) {
    try {
        const response = await fetch(`/admin/getUserByID?id=${encodeURIComponent(id)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const userData = await response.json();
        user = userData.data;
        return user;
    } catch (error) {
        console.error(`Error fetching user with ID ${id}:`, error);
        throw new Error(`Unable to fetch user with ID ${id}`);
    }
}