// Profile Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // File upload preview
    const fileInput = document.getElementById('profile_picture');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Show file info
                const fileInfo = document.querySelector('.file-upload-info');
                if (fileInfo) {
                    fileInfo.innerHTML = `
                        <p><strong>Selected file:</strong> ${file.name}</p>
                        <p>Size: ${(file.size / 1024 / 1024).toFixed(2)} MB</p>
                        <p>Type: ${file.type}</p>
                    `;
                }
            }
        });
    }

    // Form validation
    const form = document.querySelector('.profile-form');
    if (form) {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    field.style.borderColor = 'var(--error-color)';
                    isValid = false;
                } else {
                    field.style.borderColor = 'var(--border-color)';
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required fields.');
            }
        });
    }

    // Reset form confirmation
    const resetBtn = document.querySelector('.reset-btn');
    if (resetBtn) {
        resetBtn.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to reset all changes?')) {
                e.preventDefault();
            }
        });
    }

    // Auto-save draft (optional feature)
    let autoSaveTimer;
    const formInputs = form ? form.querySelectorAll('input, textarea, select') : [];
    
    formInputs.forEach(input => {
        input.addEventListener('input', function() {
            clearTimeout(autoSaveTimer);
            autoSaveTimer = setTimeout(() => {
                // Save form data to localStorage as draft
                const formData = new FormData(form);
                const draftData = {};
                
                for (let [key, value] of formData.entries()) {
                    draftData[key] = value;
                }
                
                localStorage.setItem('profile_draft', JSON.stringify(draftData));
            }, 1000);
        });
    });

    // Load draft data on page load
    const savedDraft = localStorage.getItem('profile_draft');
    if (savedDraft && form) {
        try {
            const draftData = JSON.parse(savedDraft);
            Object.keys(draftData).forEach(key => {
                const field = form.querySelector(`[name="${key}"]`);
                if (field && !field.value) {
                    field.value = draftData[key];
                }
            });
        } catch (e) {
            console.error('Error loading draft data:', e);
        }
    }

    // Clear draft after successful save
    if (form) {
        form.addEventListener('submit', function() {
            localStorage.removeItem('profile_draft');
        });
    }
});
