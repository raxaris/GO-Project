let currentPage = parseInt(document.getElementById("currentPage").innerText);

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        renderPage(currentPage);
        updatePagination();
    }
}

function nextPage() {
    currentPage++;
    renderPage(currentPage);
    updatePagination();
}

function updatePagination() {
    document.getElementById('currentPage').innerText = currentPage;
}