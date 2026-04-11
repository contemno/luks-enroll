TARGET := target

.PHONY: package changelog clean

package: changelog
	dpkg-buildpackage -us -uc -b
	mkdir -p $(TARGET)
	mv ../luks-enroll_*.deb ../luks-enroll_*.buildinfo ../luks-enroll_*.changes $(TARGET)/

changelog:
	./scripts/gen-changelog.sh

clean:
	rm -rf $(TARGET)
