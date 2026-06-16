TARGET := target

.PHONY: package changelog clean test lint

package: changelog
	dpkg-buildpackage -us -uc -b
	mkdir -p $(TARGET)
	mv ../luks-enroll_*.deb ../luks-enroll_*.buildinfo ../luks-enroll_*.changes $(TARGET)/

changelog:
	./scripts/gen-changelog.sh

test:
	python3 -m pytest tests/ -v

lint:
	ruff check .
	ruff format --check .

clean:
	rm -rf $(TARGET)
