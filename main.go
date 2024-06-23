package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"
    "runtime"
    "strconv"
    "github.com/ClickHouse/clickhouse-go/v2"
    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
    "math/rand/v2"

    "net/http"
    _ "net/http/pprof"
)

const N_total_packets = 12461224583

func check(e error) {
    if e != nil {
        log.Fatal(e)
    }
}

func main() {

	runtime.GOMAXPROCS(126)

	args := os.Args

	n_functions, err := strconv.Atoi(args[2])
    check(err)

    n_samples, err := strconv.Atoi(args[3])
    check(err)

    sign_thres, err := strconv.ParseFloat(args[4], 64)
    check(err)

    n_iterations, err := strconv.Atoi(args[5])
    check(err)
    
    limit := false 
    n_limit := 0

    if len(args) > 7 {
        if args[6] == "lim" {
            limit = true
        }
        n_limit_, err := strconv.Atoi(args[7])
        n_limit = n_limit_
        check(err)
    }

    zmap := false

    if len(args) > 8 {
        if args[8] == "zmap" {
            zmap = true
        }
    }

    if len(args) > 9 {
        if args[9] == "pprof" {
            go func() {
                log.Println("Starting pprof server on :6060")
                log.Println(http.ListenAndServe("localhost:6060", nil))
            }()
        }
    }

    times, err := ReadLines("times.txt")
    check(err)


    conn, err := connect(args[1])
    if err != nil {
        panic((err))
    }

    ctx := context.Background()

    fmt.Printf("Retrieving packets for february ")
    if zmap {
        fmt.Printf("without ZMap.\n")
    } else {
        fmt.Printf(".\n")
    }

    startDb := time.Now()
    splits, n_packets := SelectSplits(
        &ctx,
        &conn,
        times,
        limit,
        n_limit,
        zmap,
    )
    log.Printf("  Got %d packets from database.\n", n_packets)
    elapsedDb := time.Since(startDb)
    log.Printf("Time elapsed while querying database: %s\n", elapsedDb)

    start := time.Now()

    seed1 := rand.Uint64() / 2
    seed2 := rand.Uint64() / 2

    log.Printf("SEEDS: %d, %d\n", seed1, seed2)

    intersections, signs, compositions := Fgpt_ident_iterative(
        splits,
        n_functions,
        0.1,
        Initial_set,
        Binary_operations,
        Feature_extractions,
        n_samples,
        sign_thres,
        10, // Max sign
        n_iterations,
        n_packets,
        seed1, 
        seed2,
    )

    fingerprints := Map[*Intersection, *Fingerprint](
		intersections,
		func(x *Intersection) *Fingerprint {
			f_signs := Map[int, *Sign](
				x.idxs,
				func(a int) *Sign {
					return signs[a].sign
				},
			)
			return &Fingerprint{
				signs: 	f_signs,
				idxs:	x.f_idxs,
			}
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	elapsed := time.Since(start)
	fmt.Printf("Time elapsed for identifier: %s.\n", elapsed)
    fmt.Printf("Found %d fingerprints.\n", len(fingerprints))
    PrintFingerprints(fingerprints, compositions)

    f, err := os.Create("tmp/seeds")
    check(err)
    defer f.Close()

    _, err = f.WriteString(fmt.Sprintf("SEEDS: %d, %d\n", seed1, seed2))
    check(err)

    for i, inter := range intersections {
        path := fmt.Sprintf("tmp/intersection_%d", i)
        f, err = os.Create(path)
        check(err)
        fgpt := fingerprints[i]
        str := SprintFingerprint(fgpt, i, compositions)
        perc := float32(inter.size) / float32(n_packets)
        check(err)
        str += fmt.Sprintf("  , Fraction of packets: %f\n", perc)
        str += portString(inter, splits)
        n0, err := f.WriteString(str)
        check(err)
        log.Printf("Wrote %d bytes\n", n0)
        err = f.Sync()
        check(err)
    }
}

func portString(intersection *Intersection, splits []*Split) string {
    portCount := make(map[int]int)
    for _, p_idx := range intersection.packets {
        p := splits[p_idx.split_idx].packets[p_idx.packet_idx]
        port := LiftInt(get_DstPort(p))
        if _, ok := portCount[port]; ok {
            portCount[port] += 1
        } else {
            portCount[port] = 1
        }
    }
    portRatio := make(map[int]float64)
    for port, count := range portCount {
        portRatio[port] = float64(count) / float64(intersection.size)
    }
    ret := ""
    for port, ratio := range portRatio {
        ret += fmt.Sprintf("  Port %d: %f,\n", port, ratio)
    }
    return ret
}


func connect(db string) (driver.Conn, error) {
    var (
        ctx       = context.Background()
        conn, err = clickhouse.Open(&clickhouse.Options{
            Addr: []string{db},
            Auth: clickhouse.Auth{
                Database: "",
                Username: "",
                Password: "",
            },
            ClientInfo: clickhouse.ClientInfo{
                Products: []struct {
                    Name    string
                    Version string
                }{
                    {Name: "", Version: ""},
                },
            },

            Debugf: func(format string, v ...interface{}) {
                fmt.Printf(format, v)
            },
        })
    )

    if err != nil {
        return nil, err
    }

    if err := conn.Ping(ctx); err != nil {
        if exception, ok := err.(*clickhouse.Exception); ok {
            fmt.Printf("Exception [%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
        }
        return nil, err
    }
    return conn, nil
}
