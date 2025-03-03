const authSection = document.getElementById('auth-section');
const projectSection = document.getElementById('project-section');
const issueSection = document.getElementById('issue-section');
const userInfo = document.getElementById('user-info');
const loggedInUsername = document.getElementById('logged-in-username');
const searchResults = document.getElementById('search-results'); // Make sure this is defined

let currentUserId = null;
let currentProjectId = null;

// Authentication
document.getElementById('register-btn').addEventListener('click', () => {
    console.log('Register button clicked');
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value.trim();
    const email = document.getElementById('reg-email').value.trim();

    // Reset error messages
    document.getElementById('reg-username-error').textContent = '';
    document.getElementById('reg-password-error').textContent = '';
    document.getElementById('reg-email-error').textContent = '';

    let isValid = true;

    // Username validation
    if (!username) {
        document.getElementById('reg-username-error').textContent = 'Username is required.';
        document.getElementById('reg-username').style.borderColor = 'red'; // Highlight field
        isValid = false;
    }

    // Password validation
    if (!password) {
        document.getElementById('reg-password-error').textContent = 'Password is required.';
        isValid = false;
    } else if (password.length < 8) {
        document.getElementById('reg-password-error').textContent = 'Password must be at least 8 characters long.';
        isValid = false;
    }

    // Email validation
    if (!email) {
        document.getElementById('reg-email-error').textContent = 'Email is required.';
        isValid = false;
    } else if (!isValidEmail(email)) {
        document.getElementById('reg-email-error').textContent = 'Please enter a valid email address.';
        isValid = false;
    }

    if (!isValid) {
        return; // Stop form submission if validation fails
    }

    // Show loading indicator (optional)
    document.getElementById('register-btn').textContent = 'Registering...';
    console.log('Registering...'); // Log the event

    fetch('/api/users/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
                email
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data && data.message) { // Check if data and message exist
                alert(data.message);
            } else {
                alert('Registration failed. Please try again.'); // More specific error
            }
            document.getElementById('register-btn').textContent = 'Register'; // Reset button text
        })
        .catch(error => {
            console.error('Registration Error:', error); // Log the error
            alert('An error occurred during registration. Please try again.');
            document.getElementById('register-btn').textContent = 'Register'; // Reset button text
        });
});

function loadProjects() {
    console.log('LoadProjects() called');
    authSection.style.display = 'none';
    projectSection.style.display = 'block';

    fetch('/api/projects')
        .then(response => response.json())
        .then(data => {
            console.log('projects data:', data);
            const projectList = document.getElementById('project-list');
            projectList.innerHTML = '';

            data.forEach(project => {
                const projectItem = document.createElement('div');
                projectItem.textContent = project.name;

                const deleteButton = document.createElement('button');
                deleteButton.textContent = 'Delete';
                deleteButton.addEventListener('click', () => {
                    const token = localStorage.getItem('token');
                    fetch(`/api/projects/${project.id}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        })
                        .then(response => {
                            if (response.ok) {
                                loadProjects();
                            } else {
                                alert('Failed to delete project.');
                            }
                        })
                        .catch(error => {
                            console.error('Error deleting project:', error);
                            alert('An error occurred while deleting the project.');
                        });
                });

                projectItem.appendChild(deleteButton);
                projectItem.addEventListener('click', () => loadIssues(project.id));
                projectList.appendChild(projectItem);
            });
        })
        .catch(error => {
            console.error('Error loading projects:', error);
            alert('Failed to load projects. Please try again.');
        });
}

// Issues
function loadIssues(projectId) {
    currentProjectId = projectId;
    issueSection.style.display = 'block';
    loadProjectMembers(projectId); // Load project members

    fetch(`/api/projects/${projectId}/issues`)
        .then(response => response.json())
        .then(data => {
            const issueList = document.getElementById('issue-list');
            issueList.innerHTML = '';

            data.forEach(issue => {
                const issueItem = document.createElement('div');
                issueItem.textContent = issue.title;

                // Delete Issue Button
                const deleteButton = document.createElement('button');
                deleteButton.textContent = 'Delete';
                deleteButton.addEventListener('click', () => {
                    const token = localStorage.getItem('token');
                    fetch(`/api/issues/${issue.id}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        })
                        .then(response => {
                            if (response.ok) {
                                loadIssues(projectId);
                            } else {
                                alert('Failed to delete issue.');
                            }
                        })
                        .catch(error => {
                            console.error('Error deleting issue:', error);
                            alert('An error occurred while deleting the issue.');
                        });
                });

                issueItem.appendChild(deleteButton);
                issueList.appendChild(issueItem);
            });
        })
        .catch(error => {
            console.error('Error loading issues:', error);
            alert('Failed to load issues. Please try again.');
        });
}

document.getElementById('create-issue-btn').addEventListener('click', () => {
    const title = document.getElementById('issue-title').value;
    const description = document.getElementById('issue-description').value;

    fetch(`/api/projects/${currentProjectId}/issues`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                title,
                description,
                creator_id: currentUserId
            })
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadIssues(currentProjectId);
        });
});

// Email validation function
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

document.getElementById('login-btn').addEventListener('click', () => {
    console.log('Login button clicked'); // Log the event
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();

    // Reset error messages
    document.getElementById('login-username-error').textContent = '';
    document.getElementById('login-password-error').textContent = '';

    let isValid = true;

    // Username validation
    if (!username) {
        document.getElementById('login-username-error').textContent = 'Username is required.';
        isValid = false;
    }

    // Password validation
    if (!password) {
        document.getElementById('login-password-error').textContent = 'Password is required.';
        isValid = false;
    }

    if (!isValid) {
        return; // Stop form submission if validation fails
    }

    fetch('/api/users/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password
            })
        })
        .then(response => response.json()) // Parse JSON response
        .then(data => {
            if (data.token) {
                localStorage.setItem('token', data.token);
                currentUserId = data.user_id;
                loadProjects(); // Or redirect to the main page
                window.location.href = '/static/project.html'; // Redirect to the main page
            } else {
                alert(data.message || 'An error occurred during login. Please try again.');
            }
        })
        .catch(error => {
            console.error("Login Error:", error); // Log the error
            alert('An error occurred during login. Please try again.');
        });
});
console.log('Script loaded'); // Log a message to the console

document.getElementById('logout-btn').addEventListener('click', () => {
    currentUserId = null;
    authSection.style.display = 'block';
    projectSection.style.display = 'none';
    issueSection.style.display = 'none';
    userInfo.style.display = 'none';
});

// Projects
document.getElementById('create-project-btn').addEventListener('click', () => {
    const name = document.getElementById('project-name').value;
    const description = document.getElementById('project-description').value;
    // Retrieve the token (you'll need to store it somewhere after login)
    const token = localStorage.getItem('token'); // Example: Assuming you store it in localStorage

    fetch('/api/projects', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                name,
                description,
                owner_id: currentUserId
            })
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadProjects();
        });
});
document.getElementById('add-member-btn').addEventListener('click', () => {
    const username = document.getElementById('member-username').value;
    const role = document.getElementById('member-role').value;
    const token = localStorage.getItem('token');

    fetch(`/api/projects/${currentProjectId}/members`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                username,
                role
            })
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            loadProjectMembers(currentProjectId); // Reload members
        });
});

function loadProjectMembers(projectId) {
    fetch(`/api/projects/${projectId}/members`)
        .then(response => response.json())
        .then(data => {
            const memberList = document.getElementById('project-members-list');
            memberList.innerHTML = '';

            data.forEach(member => {
                const memberItem = document.createElement('li');
                memberItem.textContent = `${member.username} (${member.role})`;

                // Remove Member Button
                const removeButton = document.createElement('button');
                removeButton.textContent = 'Remove';
                removeButton.addEventListener('click', () => {
                    const token = localStorage.getItem('token');
                    fetch(`/api/projects/${projectId}/members/${member.id}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        })
                        .then(() => {
                            loadProjectMembers(projectId)
                            alert('Member removed successfully')
                        }); // Reload members
                });

                memberItem.appendChild(removeButton); // Append the button to the list item
                memberList.appendChild(memberItem);
            });
        });
}
document.addEventListener('DOMContentLoaded', function() {
    // ... (Your existing code)

    const searchUserButton = document.getElementById('search-user-btn');
    const addMemberButton = document.getElementById('add-member-btn');
    const memberUsernameInput = document.getElementById('member-username');
    const memberRoleSelect = document.getElementById('member-role');
    const projectMembersList = document.getElementById('project-members-list');

    searchUserButton.addEventListener('click', function() {
        console.log('Search user button clicked');
        const username = memberUsernameInput.value;
        if (!username) {
            alert('Please enter a username to search.');
            return;
        }

        fetch(`/api/users/search?query=${username}`)
            .then(response => response.json())
            .then(data => {
                const searchResults = document.getElementById('search-results'); // Get the search results container
                searchResults.innerHTML = ''; // Clear previous results

                if (data.length === 0) {
                    alert('User not found.');
                    return;
                }

                data.forEach(user => {
                    const userItem = document.createElement('div');
                    userItem.textContent = `${user.username} (${user.email})`;
                    userItem.dataset.userId = user.id; // Store user ID
                    searchResults.appendChild(userItem);

                    userItem.addEventListener('click', () => {
                        memberUsernameInput.value = user.username; // Populate input
                        searchUserButton.dataset.userId = user.id; // Store user ID
                        searchResults.innerHTML = ''; // Clear results
                    });
                });
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred during the search.');
            });
    });

    addMemberButton.addEventListener('click', function() {
        const userId = searchUserButton.dataset.userId;
        const role = memberRoleSelect.value;
        const projectId = currentProjectId; // Use the actual project ID

        if (!userId) {
            alert('Please search for a user first.');
            return;
        }

        fetch(`/api/projects/${projectId}/members`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // You'll need to include the authorization token here
                    // 'Authorization': 'Bearer YOUR_TOKEN'
                },
                body: JSON.stringify({
                    user_id: userId,
                    role: role
                })
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                // Optionally, update the project members list here
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while adding the member.');
            });
    });
});