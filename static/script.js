// Browser interactions para sa Campus Hardware Inventory

document.addEventListener('DOMContentLoaded', () => {

    
    const deleteButtons = document.querySelectorAll('button[type="submit"].btn-outline-danger');
    deleteButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            const confirmed = confirm('Are you sure you want to delete this equipment entry?');
            if (!confirmed) {
                event.preventDefault();
            }
        });
    });

    
    const borrowForms = document.querySelectorAll('form[action*="borrow"]');
    borrowForms.forEach(form => {
        const qtyInput = form.querySelector('input[name="quantity"]');
        if (qtyInput) {
            qtyInput.addEventListener('input', () => {
                const max = parseInt(qtyInput.getAttribute('max'), 10);
                const current = parseInt(qtyInput.value, 10);

                if (current > max) {
                    alert(`Quantity cannot exceed available stock of ${max}.`);
                    qtyInput.value = max;
                } else if (current < 1) {
                    qtyInput.value = 1;
                }
            });
        }
    });

    
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alertBox => {
            const closeBtn = alertBox.querySelector('.btn-close');
            if (closeBtn) {
                closeBtn.click();
            }
        });
    }, 5000);
});