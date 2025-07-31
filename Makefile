.PHONY: init install run clean help

init:
	npm init -y

install:
	npm install express validator bcrypt dotenv nodemailer

run:
	npm start

clean:
	rm -f db.json

help:
	@echo "Usage:"
	@echo "  make init    - Initialize project with npm init"
	@echo "  make install - Install dependencies"
	@echo "  make run     - Run the app"
	@echo "  make clean   - Remove db.json"
	@echo "  make help    - Show this help message"