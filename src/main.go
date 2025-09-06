package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akadatalimited/breathgslb/src/config"
	"github.com/akadatalimited/breathgslb/src/dnsserver"
	"github.com/akadatalimited/breathgslb/src/doc"
	"github.com/akadatalimited/breathgslb/src/healthcheck"
	"github.com/akadatalimited/breathgslb/src/logging"
	"github.com/miekg/dns"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Import all the functions from our new files
// The functions are automatically available since they're in the same package

func main() {
	// Call the main function from main_functions.go
	main()
}